package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/auth"
)

func TestRunSelectedRunsOnlyRequestedIdentityVersion(t *testing.T) {
	for _, version := range []string{"2", "3"} {
		t.Run(version, func(t *testing.T) {
			var called []string
			var stderr bytes.Buffer
			exitCode := runSelected([]string{"-version", version}, &stderr, map[string]func() int{
				"2": func() int { called = append(called, "2"); return 0 },
				"3": func() int { called = append(called, "3"); return 0 },
			})
			if exitCode != 0 {
				t.Fatalf("exit code = %d, want 0; stderr: %s", exitCode, stderr.String())
			}
			if len(called) != 1 || called[0] != version {
				t.Fatalf("called runners = %v, want only version %s", called, version)
			}
		})
	}
}

func TestRunSelectedRejectsMissingOrUnsupportedVersion(t *testing.T) {
	for _, args := range [][]string{nil, {"-version", "4"}} {
		called := false
		var stderr bytes.Buffer
		exitCode := runSelected(args, &stderr, map[string]func() int{
			"2": func() int { called = true; return 0 },
			"3": func() int { called = true; return 0 },
		})
		if exitCode != 2 {
			t.Errorf("args %v: exit code = %d, want 2", args, exitCode)
		}
		if called {
			t.Errorf("args %v: unexpectedly called a version runner", args)
		}
	}
}

func TestRunV2WithOptionsExercisesPasswordTokenAndNoAuth(t *testing.T) {
	var methods []string
	noAuthCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && request.URL.Path == "/volume/v2/tenant-name/volumes/detail" {
			noAuthCalled = true
			if request.Header.Get("X-Auth-Token") != "user-name:tenant-name" {
				t.Errorf("X-Auth-Token = %q, want synthetic v2 token", request.Header.Get("X-Auth-Token"))
			}
			_, _ = io.WriteString(w, `{"volumes": []}`)
			return
		}

		var body struct {
			Auth map[string]json.RawMessage `json:"auth"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if _, ok := body.Auth["passwordCredentials"]; ok {
			methods = append(methods, "password")
		} else if _, ok := body.Auth["token"]; ok {
			methods = append(methods, "token")
		} else {
			t.Errorf("unrecognized auth request: %s", body.Auth)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"access": {
				"token": {"id": "issued-token", "expires": "2030-01-01T00:00:00Z", "tenant": {"id": "tenant-id", "name": "tenant-name"}},
				"user": {"id": "user-id", "name": "user-name", "roles": []},
				"serviceCatalog": [{"name": "nova", "type": "compute", "endpoints": [{"region": "RegionOne", "publicURL": "http://compute.example"}]}]
			}
		}`)
	}))
	defer server.Close()

	exitCode := runV2WithOptions(context.Background(), auth.AuthOptionsV2{
		AuthURL: server.URL,
		Auth: auth.V2PasswordOpts{
			Username:    "user-name",
			Password:    "password",
			TenantID:    "tenant-id",
			TenantName:  "tenant-name",
			AllowReauth: true,
		},
	})
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	seen := map[string]bool{}
	for _, method := range methods {
		seen[method] = true
	}
	if !seen["password"] || !seen["token"] {
		t.Fatalf("auth methods exercised = %v, want password and token", methods)
	}
	if !noAuthCalled {
		t.Fatal("v2 Cinder no-auth endpoint was not exercised")
	}
}

func TestTOTPPasscodeRFC6238(t *testing.T) {
	// RFC 6238 SHA-1 test secret, encoded as base32. Keystone uses six digits.
	got, err := totpPasscode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("passcode = %q, want 287082", got)
	}
}

func TestClockOffsetFromHTTPDate(t *testing.T) {
	observed := time.Date(2026, time.October, 1, 15, 0, 2, 500_000_000, time.UTC)
	offset, err := clockOffsetFromHTTPDate("Thu, 01 Oct 2026 15:00:00 GMT", observed)
	if err != nil {
		t.Fatal(err)
	}
	if offset != -2500*time.Millisecond {
		t.Fatalf("offset = %v, want -2.5s", offset)
	}
}

func TestFreshTOTPPasscodeWaitsAcrossBoundary(t *testing.T) {
	times := []time.Time{time.Unix(29, 500_000_000), time.Unix(30, 100_000_000)}
	calls := 0
	var waited time.Duration
	got, err := freshTOTPPasscode(
		context.Background(),
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		func() time.Time {
			got := times[calls]
			calls++
			return got
		},
		func(_ context.Context, d time.Duration) error {
			waited = d
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if waited <= 500*time.Millisecond {
		t.Fatalf("waited %v, want enough time to cross the boundary", waited)
	}
	want, err := totpPasscode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", times[1])
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("passcode = %q, want post-boundary %q", got, want)
	}
}

func TestFreshTOTPPasscodeDoesNotWaitWithSufficientValidity(t *testing.T) {
	now := time.Unix(10, 0)
	waited := false
	_, err := freshTOTPPasscode(
		context.Background(),
		"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ",
		func() time.Time { return now },
		func(context.Context, time.Duration) error {
			waited = true
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if waited {
		t.Fatal("unexpected boundary wait")
	}
}

type staticAuthenticator struct {
	result auth.AuthResult
}

func (a staticAuthenticator) Authenticate(context.Context, *gophercloud.ProviderClient) (*auth.AuthResult, error) {
	result := a.result
	return &result, nil
}

func (staticAuthenticator) GetAuthURL() string { return "http://identity.example/" }

func TestCloudAuthDataFlattensCredentialsAndScope(t *testing.T) {
	data, err := cloudAuthData("https://identity.example/v3", auth.V3PasswordOpts{
		Username:       "cloud-user",
		Password:       "cloud-password",
		UserDomainName: "users",
		AllowReauth:    true,
	}, &auth.Scope{
		ProjectName:       "project",
		ProjectDomainName: "projects",
	})
	if err != nil {
		t.Fatal(err)
	}

	want := map[string]any{
		"auth_url":            "https://identity.example/v3",
		"username":            "cloud-user",
		"password":            "cloud-password",
		"user_domain_name":    "users",
		"allow_reauth":        true,
		"project_name":        "project",
		"project_domain_name": "projects",
	}
	if len(data) != len(want) {
		t.Fatalf("auth data = %#v, want %#v", data, want)
	}
	for key, expected := range want {
		if data[key] != expected {
			t.Errorf("auth data[%q] = %#v, want %#v", key, data[key], expected)
		}
	}
}

func TestAuthOptionsFromTempCloudParsesFileAndRemovesIt(t *testing.T) {
	dir := t.TempDir()
	options, err := authOptionsFromTempCloud(dir, auth.AuthV3Password, map[string]any{
		"auth_url":   "https://identity.example/v3",
		"username":   "cloud-user",
		"password":   "cloud-password",
		"project_id": "project-id",
	}, auth.WithAllowReauth(false))
	if err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("temporary directory contains %d entries after parsing, want 0", len(entries))
	}

	v3, ok := options.(auth.AuthOptionsV3)
	if !ok {
		t.Fatalf("options have type %T, want auth.AuthOptionsV3", options)
	}
	if v3.AuthURL != "https://identity.example/v3" {
		t.Fatalf("AuthURL = %q, want %q", v3.AuthURL, "https://identity.example/v3")
	}
	password, ok := v3.Auth.(auth.V3PasswordOpts)
	if !ok {
		t.Fatalf("auth options have type %T, want auth.V3PasswordOpts", v3.Auth)
	}
	if password.Username != "cloud-user" || password.Password != "cloud-password" {
		t.Fatalf("password credentials = %#v, want cloud-user/cloud-password", password)
	}
	if password.Scope == nil || password.Scope.ProjectID != "project-id" {
		t.Fatalf("scope = %#v, want project-id", password.Scope)
	}
	if password.AllowReauth {
		t.Fatal("AllowReauth = true, want false override")
	}
}

func TestAuthOptionsFromTempCloudUsesAnIsolatedDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/secure.yaml", []byte("not: [valid"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := authOptionsFromTempCloud(dir, auth.AuthV3Token, map[string]any{
		"auth_url": "https://identity.example/v3",
		"token":    "cloud-token",
	})
	if err != nil {
		t.Fatalf("ambient secure.yaml affected temporary cloud: %v", err)
	}
}

func TestRunAuthCaseRebuildsOptionsForEachRequest(t *testing.T) {
	calls := 0
	r := newRunner()
	build := func(context.Context) (auth.Authenticator, error) {
		calls++
		return staticAuthenticator{result: auth.AuthResult{
			TokenID: "token",
			Methods: []auth.AuthType{auth.AuthToken},
			User:    auth.User{ID: "user-id"},
		}}, nil
	}
	runAuthCaseBuilder(context.Background(), r, "dynamic", build, expectation{
		methods: []auth.AuthType{auth.AuthToken},
		userID:  "user-id",
	})
	if calls != 2 {
		t.Fatalf("builder calls = %d, want 2", calls)
	}
	if r.passed != 2 || r.failed != 0 {
		t.Fatalf("passed=%d failed=%d, want 2/0", r.passed, r.failed)
	}
}

func TestCinderNoAuthEndpoint(t *testing.T) {
	for _, test := range []struct {
		version int
		want    string
	}{
		{version: 2, want: "http://10.0.78.90/volume/v2/"},
		{version: 3, want: "http://10.0.78.90/volume/v3/"},
	} {
		got, err := cinderNoAuthEndpoint("http://10.0.78.90/identity", test.version)
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Errorf("version %d endpoint = %q, want %q", test.version, got, test.want)
		}
	}
}

func TestScopeCasesCoverAvailableV3Scopes(t *testing.T) {
	fixture := fixtureData{
		projectID:         "project-id",
		projectName:       "project-name",
		projectDomainID:   "project-domain-id",
		projectDomainName: "project-domain-name",
		domainID:          "domain-id",
		domainName:        "domain-name",
		trustID:           "trust-id",
	}

	cases := scopeCases(fixture)
	wantNames := []string{
		"unscoped/nil",
		"unscoped/empty",
		"project/id",
		"project/name-domain-id",
		"project/name-domain-name",
		"domain/id",
		"domain/name",
		"system/all",
		"trust/id",
	}
	if len(cases) != len(wantNames) {
		t.Fatalf("got %d scope cases, want %d", len(cases), len(wantNames))
	}
	for i, want := range wantNames {
		if cases[i].name != want {
			t.Errorf("case %d name = %q, want %q", i, cases[i].name, want)
		}
	}
}

func TestTokenAuthMethodsIncludeOriginalPasswordMethod(t *testing.T) {
	got := tokenAuthMethods()
	want := []auth.AuthType{auth.AuthPassword, auth.AuthToken}
	if len(got) != len(want) {
		t.Fatalf("got methods %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got methods %v, want %v", got, want)
		}
	}
}

func TestValidateAuthResult(t *testing.T) {
	base := auth.AuthResult{
		TokenID:   "token",
		Methods:   []auth.AuthType{auth.AuthV3Password},
		User:      auth.User{ID: "user-id"},
		Project:   &auth.Project{ID: "project-id"},
		CanReauth: true,
	}

	if err := validateAuthResult(&base, expectation{
		methods:   []auth.AuthType{auth.AuthV3Password},
		userID:    "user-id",
		projectID: "project-id",
		canReauth: boolPtr(true),
	}); err != nil {
		t.Fatalf("valid result rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*auth.AuthResult)
	}{
		{"missing token", func(r *auth.AuthResult) { r.TokenID = "" }},
		{"wrong method", func(r *auth.AuthResult) { r.Methods = []auth.AuthType{auth.AuthV3Token} }},
		{"wrong user", func(r *auth.AuthResult) { r.User.ID = "other" }},
		{"wrong project", func(r *auth.AuthResult) { r.Project.ID = "other" }},
		{"wrong reauth", func(r *auth.AuthResult) { r.CanReauth = false }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := base
			project := *base.Project
			got.Project = &project
			tt.mutate(&got)
			if err := validateAuthResult(&got, expectation{
				methods:   []auth.AuthType{auth.AuthV3Password},
				userID:    "user-id",
				projectID: "project-id",
				canReauth: boolPtr(true),
			}); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestSupportedEC2CasesMatchCurrentKeystoneCapabilities(t *testing.T) {
	cases := supportedEC2Cases(fixtureData{ec2Access: "access", ec2Secret: "secret"})
	want := []string{"v4-default", "v2-hmac-sha256"}
	if len(cases) != len(want) {
		t.Fatalf("got %d EC2 cases, want %d", len(cases), len(want))
	}
	for i := range want {
		if cases[i].name != want[i] {
			t.Errorf("case %d name = %q, want %q", i, cases[i].name, want[i])
		}
	}
}

func TestRunnerSummaryAndExitStatus(t *testing.T) {
	r := newRunner()
	r.run("pass", func() error { return nil })
	r.run("fail", func() error { return errors.New("boom") })
	r.skip("skip", "not configured")

	if r.passed != 1 || r.failed != 1 || r.skipped != 1 {
		t.Fatalf("unexpected counts: passed=%d failed=%d skipped=%d", r.passed, r.failed, r.skipped)
	}
	if r.exitCode() != 1 {
		t.Fatalf("exit code = %d, want 1", r.exitCode())
	}
}
