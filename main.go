package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/gophercloud/gophercloud/v2"
	"github.com/gophercloud/gophercloud/v2/auth"
	"github.com/gophercloud/gophercloud/v2/openstack"
	blockstoragenoauth "github.com/gophercloud/gophercloud/v2/openstack/blockstorage/noauth"
	"github.com/gophercloud/gophercloud/v2/openstack/config/clouds"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/applicationcredentials"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/credentials"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/ec2credentials"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/oauth1"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/roles"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/trusts"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/users"
	"go.yaml.in/yaml/v3"
)

type fixtureData struct {
	authURL                     string
	username                    string
	userID                      string
	password                    string
	userDomainID                string
	userDomainName              string
	projectID                   string
	projectName                 string
	projectDomainID             string
	projectDomainName           string
	domainID                    string
	domainName                  string
	trustID                     string
	trusteeID                   string
	trusteeName                 string
	trusteePassword             string
	totpSecret                  string
	clockOffset                 time.Duration
	applicationCredentialID     string
	applicationCredentialName   string
	applicationCredentialSecret string
	ec2Access                   string
	ec2Secret                   string
	oauthConsumerID             string
	oauthConsumerSecret         string
	oauthAccess                 map[oauth1.SignatureMethod]*oauth1.Token
}

type scopeCase struct {
	name      string
	scope     *auth.Scope
	projectID string
	domainID  string
	system    bool
	trustID   string
}

type expectation struct {
	methods                 []auth.AuthType
	userID                  string
	projectID               string
	domainID                string
	system                  bool
	trustID                 string
	applicationCredentialID string
	canReauth               *bool
	scoped                  bool
}

type runner struct {
	passed  int
	failed  int
	skipped int
}

func newRunner() *runner {
	return &runner{}
}

func (r *runner) run(name string, test func() error) {
	if err := test(); err != nil {
		r.failed++
		fmt.Printf("FAIL  %-72s %v\n", name, err)
		return
	}
	r.passed++
	fmt.Printf("PASS  %s\n", name)
}

func (r *runner) skip(name, reason string) {
	r.skipped++
	fmt.Printf("SKIP  %-72s %s\n", name, reason)
}

func (r *runner) exitCode() int {
	if r.failed != 0 {
		return 1
	}
	return 0
}

func (r *runner) summary() {
	fmt.Printf("\nSUMMARY: %d passed, %d failed, %d skipped\n", r.passed, r.failed, r.skipped)
}

func boolPtr(v bool) *bool {
	return &v
}

const (
	totpPeriod        = 30 * time.Second
	totpRequestBudget = 5 * time.Second
	totpBoundarySlack = 100 * time.Millisecond
)

func totpPasscode(secret string, now time.Time) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret += strings.Repeat("=", (8-len(secret)%8)%8)
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, key)
	if _, err := mac.Write(counter); err != nil {
		return "", err
	}
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1_000_000), nil
}

func totpBoundaryWait(now time.Time) time.Duration {
	elapsed := time.Duration(now.UnixNano() % int64(totpPeriod))
	if elapsed < 0 {
		elapsed += totpPeriod
	}
	remaining := totpPeriod - elapsed
	if remaining > totpRequestBudget {
		return 0
	}
	return remaining + totpBoundarySlack
}

func waitForContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func freshTOTPPasscode(ctx context.Context, secret string, now func() time.Time, wait func(context.Context, time.Duration) error) (string, error) {
	current := now()
	if duration := totpBoundaryWait(current); duration > 0 {
		if err := wait(ctx, duration); err != nil {
			return "", err
		}
		current = now()
	}
	return totpPasscode(secret, current)
}

func clockOffsetFromHTTPDate(date string, observed time.Time) (time.Duration, error) {
	serverTime, err := http.ParseTime(date)
	if err != nil {
		return 0, err
	}
	return serverTime.Sub(observed), nil
}

func measureServerClockOffset(ctx context.Context, endpoint string) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, err
	}
	before := time.Now()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	observed := before.Add(time.Since(before) / 2)
	return clockOffsetFromHTTPDate(resp.Header.Get("Date"), observed)
}

func cinderNoAuthEndpoint(authURL string, version int) (string, error) {
	u, err := url.Parse(authURL)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid auth URL %q", authURL)
	}
	u.Path = fmt.Sprintf("/volume/v%d/", version)
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func scopeCases(f fixtureData) []scopeCase {
	return []scopeCase{
		{name: "unscoped/nil", scope: nil},
		{name: "unscoped/empty", scope: &auth.Scope{}},
		{name: "project/id", scope: &auth.Scope{ProjectID: f.projectID}, projectID: f.projectID},
		{name: "project/name-domain-id", scope: &auth.Scope{ProjectName: f.projectName, ProjectDomainID: f.projectDomainID}, projectID: f.projectID},
		{name: "project/name-domain-name", scope: &auth.Scope{ProjectName: f.projectName, ProjectDomainName: f.projectDomainName}, projectID: f.projectID},
		{name: "domain/id", scope: &auth.Scope{DomainID: f.domainID}, domainID: f.domainID},
		{name: "domain/name", scope: &auth.Scope{DomainName: f.domainName}, domainID: f.domainID},
		{name: "system/all", scope: &auth.Scope{System: true}, system: true},
		{name: "trust/id", scope: &auth.Scope{TrustID: f.trustID}, projectID: f.projectID, trustID: f.trustID},
	}
}

func tokenAuthMethods() []auth.AuthType {
	// Keystone preserves the authentication method history of the original
	// token and appends the token method when it issues a new token.
	return []auth.AuthType{auth.AuthPassword, auth.AuthToken}
}

func expectationForScope(s scopeCase, methods []auth.AuthType, userID string, canReauth bool) expectation {
	return expectation{
		methods:   methods,
		userID:    userID,
		projectID: s.projectID,
		domainID:  s.domainID,
		system:    s.system,
		trustID:   s.trustID,
		canReauth: boolPtr(canReauth),
		scoped:    s.projectID != "" || s.domainID != "" || s.system || s.trustID != "",
	}
}

func validateAuthResult(result *auth.AuthResult, want expectation) error {
	if result == nil {
		return errors.New("nil AuthResult")
	}
	if result.TokenID == "" {
		return errors.New("empty token ID")
	}
	gotMethods := slices.Clone(result.Methods)
	wantMethods := slices.Clone(want.methods)
	slices.Sort(gotMethods)
	slices.Sort(wantMethods)
	if !slices.Equal(gotMethods, wantMethods) {
		return fmt.Errorf("methods = %v, want %v", result.Methods, want.methods)
	}
	if want.userID != "" && result.User.ID != want.userID {
		return fmt.Errorf("user ID = %q, want %q", result.User.ID, want.userID)
	}
	if want.projectID != "" {
		if result.Project == nil || result.Project.ID != want.projectID {
			return fmt.Errorf("project = %#v, want ID %q", result.Project, want.projectID)
		}
	} else if result.Project != nil {
		return fmt.Errorf("unexpected project scope %q", result.Project.ID)
	}
	if want.domainID != "" {
		if result.Domain == nil || result.Domain.ID != want.domainID {
			return fmt.Errorf("domain = %#v, want ID %q", result.Domain, want.domainID)
		}
	} else if result.Domain != nil {
		return fmt.Errorf("unexpected domain scope %q", result.Domain.ID)
	}
	if result.System != want.system {
		return fmt.Errorf("system scope = %t, want %t", result.System, want.system)
	}
	if want.trustID != "" {
		if result.Trust == nil || result.Trust.ID != want.trustID {
			return fmt.Errorf("trust = %#v, want ID %q", result.Trust, want.trustID)
		}
	} else if result.Trust != nil {
		return fmt.Errorf("unexpected trust %q", result.Trust.ID)
	}
	if want.applicationCredentialID != "" {
		if result.ApplicationCredential == nil || result.ApplicationCredential.ID != want.applicationCredentialID {
			return fmt.Errorf("application credential = %#v, want ID %q", result.ApplicationCredential, want.applicationCredentialID)
		}
	}
	if want.canReauth != nil && result.CanReauth != *want.canReauth {
		return fmt.Errorf("CanReauth = %t, want %t", result.CanReauth, *want.canReauth)
	}
	if want.scoped && len(result.Catalog.Entries) == 0 {
		return errors.New("scoped token has an empty service catalog")
	}
	if !want.scoped && len(result.Catalog.Entries) != 0 {
		return fmt.Errorf("unscoped token has %d catalog entries", len(result.Catalog.Entries))
	}
	return nil
}

type authCaseBuilder func(context.Context) (auth.Authenticator, error)

func cloudAuthData(authURL string, credentials any, scope *auth.Scope) (map[string]any, error) {
	encoded, err := json.Marshal(credentials)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	if err := json.Unmarshal(encoded, &data); err != nil {
		return nil, err
	}
	data["auth_url"] = authURL
	if scope == nil {
		return data, nil
	}

	if scope.DomainID != "" {
		data["domain_id"] = scope.DomainID
	}
	if scope.DomainName != "" {
		data["domain_name"] = scope.DomainName
	}
	if scope.ProjectDomainID != "" {
		data["project_domain_id"] = scope.ProjectDomainID
	}
	if scope.ProjectDomainName != "" {
		data["project_domain_name"] = scope.ProjectDomainName
	}
	if scope.ProjectID != "" {
		data["project_id"] = scope.ProjectID
	}
	if scope.ProjectName != "" {
		data["project_name"] = scope.ProjectName
	}
	if scope.System {
		data["system_scope"] = "all"
	}
	if scope.TrustID != "" {
		data["trust_id"] = scope.TrustID
	}
	return data, nil
}

func authOptionsFromTempCloud(dir string, authType auth.AuthType, authData map[string]any, opts ...auth.CloudOption) (auth.Authenticator, error) {
	tempDir, err := os.MkdirTemp(dir, "gophercloud-cloud-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tempDir)

	file, err := os.CreateTemp(tempDir, "clouds-*.yaml")
	if err != nil {
		return nil, err
	}
	name := file.Name()

	config := clouds.Clouds{Clouds: map[string]clouds.Cloud{
		"gophercloud-auth-test": {AuthType: authType, Auth: authData},
	}}
	if err := yaml.NewEncoder(file).Encode(config); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}

	cloud, _, _, err := clouds.Parse(
		clouds.WithCloudName("gophercloud-auth-test"),
		clouds.WithLocations(name),
	)
	if err != nil {
		return nil, err
	}
	return cloud.ToAuthOptions(opts...)
}

func runAuthCase(ctx context.Context, r *runner, name string, options auth.Authenticator, want expectation) {
	runAuthCaseBuilder(ctx, r, name, func(context.Context) (auth.Authenticator, error) {
		return options, nil
	}, want)
}

func runAuthCaseBuilder(ctx context.Context, r *runner, name string, build authCaseBuilder, want expectation) {
	r.run(name+"/AuthResult", func() error {
		options, err := build(ctx)
		if err != nil {
			return err
		}
		result, err := options.Authenticate(ctx, nil)
		if err != nil {
			return err
		}
		return validateAuthResult(result, want)
	})

	r.run(name+"/ProviderClient", func() error {
		options, err := build(ctx)
		if err != nil {
			return err
		}
		provider, err := openstack.AuthenticatedClient(ctx, options)
		if err != nil {
			return err
		}
		if provider.TokenID == "" {
			return errors.New("ProviderClient has an empty token")
		}
		result, ok := provider.GetAuthResult().(*auth.AuthResult)
		if !ok {
			return fmt.Errorf("ProviderClient auth result has type %T", provider.GetAuthResult())
		}
		if err := validateAuthResult(result, want); err != nil {
			return err
		}
		if want.canReauth != nil && *want.canReauth {
			if provider.ReauthFunc == nil {
				return errors.New("reauthentication requested but ReauthFunc is nil")
			}
			if err := provider.ReauthFunc(ctx); err != nil {
				return fmt.Errorf("reauthentication failed: %w", err)
			}
		} else if provider.ReauthFunc != nil {
			return errors.New("unexpected ReauthFunc")
		}
		return nil
	})
}

func randomString(prefix string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

func setupFixtures(ctx context.Context) (fixtureData, *gophercloud.ServiceClient, func() []error, error) {
	var f fixtureData
	var cleanups []func() error
	cleanup := func() []error {
		var errs []error
		for i := len(cleanups) - 1; i >= 0; i-- {
			if err := cleanups[i](); err != nil {
				errs = append(errs, err)
			}
		}
		return errs
	}

	options, err := auth.AuthOptionsFromEnvV3()
	if err != nil {
		return f, nil, cleanup, fmt.Errorf("load admin environment: %w", err)
	}
	passwordOpts, ok := options.Auth.(auth.V3PasswordOpts)
	if !ok {
		return f, nil, cleanup, fmt.Errorf("admin environment produced %T, want auth.V3PasswordOpts", options.Auth)
	}
	provider, err := openstack.AuthenticatedClient(ctx, options)
	if err != nil {
		return f, nil, cleanup, fmt.Errorf("authenticate setup client: %w", err)
	}
	result, ok := provider.GetAuthResult().(*auth.AuthResult)
	if !ok {
		return f, nil, cleanup, fmt.Errorf("setup auth result has type %T", provider.GetAuthResult())
	}
	if result.Project == nil || result.Project.Domain == nil || result.User.Domain == nil {
		return f, nil, cleanup, errors.New("admin token lacks project or domain metadata")
	}
	identity, err := openstack.NewIdentityV3(ctx, provider, gophercloud.EndpointOpts{})
	if err != nil {
		return f, nil, cleanup, fmt.Errorf("create identity client: %w", err)
	}

	f = fixtureData{
		authURL:           options.AuthURL,
		username:          result.User.Name,
		userID:            result.User.ID,
		password:          passwordOpts.Password,
		userDomainID:      result.User.Domain.ID,
		userDomainName:    result.User.Domain.Name,
		projectID:         result.Project.ID,
		projectName:       result.Project.Name,
		projectDomainID:   result.Project.Domain.ID,
		projectDomainName: result.Project.Domain.Name,
		domainID:          result.User.Domain.ID,
		domainName:        result.User.Domain.Name,
		oauthAccess:       make(map[oauth1.SignatureMethod]*oauth1.Token),
	}
	f.clockOffset, err = measureServerClockOffset(ctx, f.authURL)
	if err != nil {
		return f, identity, cleanup, fmt.Errorf("measure Keystone clock offset: %w", err)
	}

	name, err := randomString("gophercloud-auth-test-")
	if err != nil {
		return f, identity, cleanup, err
	}
	trusteePassword, err := randomString("pw-")
	if err != nil {
		return f, identity, cleanup, err
	}
	trustee, err := users.Create(ctx, identity, users.CreateOpts{
		Name:     name,
		DomainID: f.userDomainID,
		Enabled:  boolPtr(true),
		Password: trusteePassword,
	}).Extract()
	if err != nil {
		return f, identity, cleanup, fmt.Errorf("create trustee user: %w", err)
	}
	f.trusteeID, f.trusteeName, f.trusteePassword = trustee.ID, trustee.Name, trusteePassword
	cleanups = append(cleanups, func() error {
		return users.Delete(ctx, identity, trustee.ID).ExtractErr()
	})

	if len(result.Roles) == 0 {
		return f, identity, cleanup, errors.New("admin token has no roles to assign to test user")
	}
	roleID := result.Roles[0].ID
	assignments := []roles.AssignOpts{
		{UserID: trustee.ID, ProjectID: f.projectID},
		{UserID: trustee.ID, DomainID: f.domainID},
		{UserID: trustee.ID, System: true},
	}
	for _, assignment := range assignments {
		if err := roles.Assign(ctx, identity, roleID, assignment).ExtractErr(); err != nil {
			return f, identity, cleanup, fmt.Errorf("assign temporary user role: %w", err)
		}
		a := assignment
		cleanups = append(cleanups, func() error {
			return roles.Unassign(ctx, identity, roleID, roles.UnassignOpts{
				UserID:    a.UserID,
				ProjectID: a.ProjectID,
				DomainID:  a.DomainID,
				System:    a.System,
			}).ExtractErr()
		})
	}

	secretBytes := make([]byte, 20)
	if _, err := rand.Read(secretBytes); err != nil {
		return f, identity, cleanup, err
	}
	f.totpSecret = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secretBytes)
	totpCredential, err := credentials.Create(ctx, identity, credentials.CreateOpts{
		Blob:   f.totpSecret,
		Type:   "totp",
		UserID: trustee.ID,
	}).Extract()
	if err != nil {
		return f, identity, cleanup, fmt.Errorf("create TOTP credential: %w", err)
	}
	cleanups = append(cleanups, func() error {
		return credentials.Delete(ctx, identity, totpCredential.ID).ExtractErr()
	})

	trustRoles := make([]trusts.Role, 0, len(result.Roles))
	for _, role := range result.Roles {
		trustRoles = append(trustRoles, trusts.Role{ID: role.ID})
	}
	trust, err := trusts.Create(ctx, identity, trusts.CreateOpts{
		Impersonation: true,
		TrusteeUserID: trustee.ID,
		TrustorUserID: f.userID,
		ProjectID:     f.projectID,
		Roles:         trustRoles,
	}).Extract()
	if err != nil {
		return f, identity, cleanup, fmt.Errorf("create trust: %w", err)
	}
	f.trustID = trust.ID
	cleanups = append(cleanups, func() error {
		return trusts.Delete(ctx, identity, trust.ID).ExtractErr()
	})

	appCredName, err := randomString("gophercloud-auth-test-")
	if err != nil {
		return f, identity, cleanup, err
	}
	appCred, err := applicationcredentials.Create(ctx, identity, f.userID, applicationcredentials.CreateOpts{
		Name:         appCredName,
		Description:  "temporary gophercloud auth matrix credential",
		Unrestricted: true,
	}).Extract()
	if err != nil {
		return f, identity, cleanup, fmt.Errorf("create application credential: %w", err)
	}
	f.applicationCredentialID = appCred.ID
	f.applicationCredentialName = appCred.Name
	f.applicationCredentialSecret = appCred.Secret
	cleanups = append(cleanups, func() error {
		return applicationcredentials.Delete(ctx, identity, f.userID, appCred.ID).ExtractErr()
	})

	ec2, err := ec2credentials.Create(ctx, identity, f.userID, ec2credentials.CreateOpts{TenantID: f.projectID}).Extract()
	if err != nil {
		return f, identity, cleanup, fmt.Errorf("create EC2 credential: %w", err)
	}
	f.ec2Access, f.ec2Secret = ec2.Access, ec2.Secret
	cleanups = append(cleanups, func() error {
		return ec2credentials.Delete(ctx, identity, f.userID, ec2.Access).ExtractErr()
	})

	consumer, err := oauth1.CreateConsumer(ctx, identity, oauth1.CreateConsumerOpts{Description: "temporary gophercloud auth matrix consumer"}).Extract()
	if err != nil {
		return f, identity, cleanup, fmt.Errorf("create OAuth1 consumer: %w", err)
	}
	f.oauthConsumerID, f.oauthConsumerSecret = consumer.ID, consumer.Secret
	cleanups = append(cleanups, func() error {
		return oauth1.DeleteConsumer(ctx, identity, consumer.ID).ExtractErr()
	})

	for _, method := range []oauth1.SignatureMethod{oauth1.HMACSHA1, oauth1.PLAINTEXT} {
		requestToken, err := oauth1.RequestToken(ctx, identity, oauth1.RequestTokenOpts{
			OAuthConsumerKey:     consumer.ID,
			OAuthConsumerSecret:  consumer.Secret,
			OAuthSignatureMethod: method,
			RequestedProjectID:   f.projectID,
		}).Extract()
		if err != nil {
			return f, identity, cleanup, fmt.Errorf("request OAuth1 %s token: %w", method, err)
		}
		authorized, err := oauth1.AuthorizeToken(ctx, identity, requestToken.OAuthToken, oauth1.AuthorizeTokenOpts{
			Roles: []oauth1.Role{{ID: result.Roles[0].ID}},
		}).Extract()
		if err != nil {
			return f, identity, cleanup, fmt.Errorf("authorize OAuth1 %s token: %w", method, err)
		}
		access, err := oauth1.CreateAccessToken(ctx, identity, oauth1.CreateAccessTokenOpts{
			OAuthConsumerKey:     consumer.ID,
			OAuthConsumerSecret:  consumer.Secret,
			OAuthToken:           requestToken.OAuthToken,
			OAuthTokenSecret:     requestToken.OAuthTokenSecret,
			OAuthVerifier:        authorized.OAuthVerifier,
			OAuthSignatureMethod: method,
		}).Extract()
		if err != nil {
			return f, identity, cleanup, fmt.Errorf("create OAuth1 %s access token: %w", method, err)
		}
		f.oauthAccess[method] = access
		accessID := access.OAuthToken
		cleanups = append(cleanups, func() error {
			return oauth1.RevokeAccessToken(ctx, identity, f.userID, accessID).ExtractErr()
		})
	}

	return f, identity, cleanup, nil
}

func passwordOptions(f fixtureData, identity string, scope *auth.Scope, allowReauth bool, trustee bool) auth.AuthOptionsV3 {
	opts := auth.V3PasswordOpts{Password: f.password, Scope: scope, AllowReauth: allowReauth}
	if trustee {
		opts.Password = f.trusteePassword
	}
	switch identity {
	case "user-id":
		if trustee {
			opts.UserID = f.trusteeID
		} else {
			opts.UserID = f.userID
		}
	case "username-domain-id":
		if trustee {
			opts.Username = f.trusteeName
		} else {
			opts.Username = f.username
		}
		opts.UserDomainID = f.userDomainID
	case "username-domain-name":
		if trustee {
			opts.Username = f.trusteeName
		} else {
			opts.Username = f.username
		}
		opts.UserDomainName = f.userDomainName
	}
	return auth.AuthOptionsV3{AuthURL: f.authURL, Auth: opts}
}

func runPasswordMatrix(ctx context.Context, r *runner, f fixtureData) {
	for _, identity := range []string{"user-id", "username-domain-id", "username-domain-name"} {
		for _, allowReauth := range []bool{false, true} {
			for _, scope := range scopeCases(f)[:8] {
				name := fmt.Sprintf("v3/password/%s/%s/reauth=%t", identity, scope.name, allowReauth)
				options := passwordOptions(f, identity, scope.scope, allowReauth, false)
				runAuthCase(ctx, r, name, options, expectationForScope(scope, []auth.AuthType{auth.AuthPassword}, f.userID, allowReauth))
			}
		}
	}
	trustScope := scopeCases(f)[8]
	for _, identity := range []string{"user-id", "username-domain-id", "username-domain-name"} {
		for _, allowReauth := range []bool{false, true} {
			name := fmt.Sprintf("v3/password/%s/%s/reauth=%t", identity, trustScope.name, allowReauth)
			options := passwordOptions(f, identity, trustScope.scope, allowReauth, true)
			want := expectationForScope(trustScope, []auth.AuthType{auth.AuthPassword}, f.userID, allowReauth)
			runAuthCase(ctx, r, name, options, want)
		}
	}
}

func unscopedToken(ctx context.Context, f fixtureData, trustee bool) (string, error) {
	options := passwordOptions(f, "user-id", nil, false, trustee)
	result, err := options.Authenticate(ctx, nil)
	if err != nil {
		return "", err
	}
	return result.TokenID, nil
}

func runTokenAndRescopeMatrix(ctx context.Context, r *runner, f fixtureData) {
	adminToken, err := unscopedToken(ctx, f, false)
	if err != nil {
		r.run("v3/token/setup-admin-unscoped", func() error { return err })
		return
	}
	trusteeToken, err := unscopedToken(ctx, f, true)
	if err != nil {
		r.run("v3/token/setup-trustee-unscoped", func() error { return err })
		return
	}

	for _, scope := range scopeCases(f) {
		token, expectedUser := adminToken, f.userID
		if scope.trustID != "" {
			token = trusteeToken
			expectedUser = f.userID // impersonating trust returns the trustor
		}
		want := expectationForScope(scope, tokenAuthMethods(), expectedUser, false)
		direct := auth.AuthOptionsV3{AuthURL: f.authURL, Auth: auth.V3TokenOpts{Token: token, Scope: scope.scope}}
		runAuthCase(ctx, r, "v3/token/"+scope.name, direct, want)

		if scope.scope != nil {
			rescope := auth.AuthOptionsV3{AuthURL: f.authURL, Auth: auth.V3TokenOpts{Token: token, Scope: scope.scope}}
			runAuthCase(ctx, r, "v3/rescope-unscoped-token/"+scope.name, rescope, want)
		}
	}
}

func totpOptions(f fixtureData, identity string, scope *auth.Scope, passcode string) auth.AuthOptionsV3 {
	opts := auth.V3TOTPOpts{Passcode: passcode, Scope: scope}
	switch identity {
	case "user-id":
		opts.UserID = f.trusteeID
	case "username-domain-id":
		opts.Username = f.trusteeName
		opts.UserDomainID = f.userDomainID
	case "username-domain-name":
		opts.Username = f.trusteeName
		opts.UserDomainName = f.userDomainName
	}
	return auth.AuthOptionsV3{AuthURL: f.authURL, Auth: opts}
}

func runTOTPMatrix(ctx context.Context, r *runner, f fixtureData) {
	for _, identity := range []string{"user-id", "username-domain-id", "username-domain-name"} {
		for _, scope := range scopeCases(f) {
			expectedUser := f.trusteeID
			if scope.trustID != "" {
				expectedUser = f.userID
			}
			want := expectationForScope(scope, []auth.AuthType{"totp"}, expectedUser, false)
			build := func(ctx context.Context) (auth.Authenticator, error) {
				passcode, err := freshTOTPPasscode(ctx, f.totpSecret, func() time.Time {
					return time.Now().Add(f.clockOffset)
				}, waitForContext)
				if err != nil {
					return nil, err
				}
				return totpOptions(f, identity, scope.scope, passcode), nil
			}
			runAuthCaseBuilder(ctx, r, "v3/totp/"+identity+"/"+scope.name, build, want)
		}
	}
}

func runPasswordTOTPMatrix(ctx context.Context, r *runner, f fixtureData, identity *gophercloud.ServiceClient) {
	_, err := users.Update(ctx, identity, f.trusteeID, users.UpdateOpts{Options: map[users.Option]any{
		users.MultiFactorAuthEnabled: true,
		users.MultiFactorAuthRules:   []any{[]string{"password", "totp"}},
	}}).Extract()
	if err != nil {
		r.run("v3/multifactor/password+totp/setup", func() error { return err })
		return
	}

	for _, userIdentity := range []string{"user-id", "username-domain-id", "username-domain-name"} {
		for _, scope := range scopeCases(f) {
			expectedUser := f.trusteeID
			if scope.trustID != "" {
				expectedUser = f.userID
			}
			want := expectationForScope(scope, []auth.AuthType{auth.AuthPassword, "totp"}, expectedUser, false)
			build := func(ctx context.Context) (auth.Authenticator, error) {
				passcode, err := freshTOTPPasscode(ctx, f.totpSecret, func() time.Time {
					return time.Now().Add(f.clockOffset)
				}, waitForContext)
				if err != nil {
					return nil, err
				}
				password := passwordOptions(f, userIdentity, nil, false, true).Auth.(auth.V3PasswordOpts)
				totp := totpOptions(f, userIdentity, nil, passcode).Auth.(auth.V3TOTPOpts)
				return auth.AuthOptionsV3{AuthURL: f.authURL, Auth: auth.V3MultifactorOpts{
					AuthMethods: []auth.AuthOptionsBuilderV3{password, totp},
					Scope:       scope.scope,
				}}, nil
			}
			runAuthCaseBuilder(ctx, r, "v3/multifactor/password+totp/"+userIdentity+"/"+scope.name, build, want)
		}
	}
}

func runMultifactorMatrix(ctx context.Context, r *runner, f fixtureData) {
	token, err := unscopedToken(ctx, f, false)
	if err != nil {
		r.run("v3/multifactor/setup-unscoped-token", func() error { return err })
		return
	}
	for _, scope := range scopeCases(f)[:8] {
		options := auth.AuthOptionsV3{
			AuthURL: f.authURL,
			Auth: auth.V3MultifactorOpts{
				AuthMethods: []auth.AuthOptionsBuilderV3{
					auth.V3PasswordOpts{UserID: f.userID, Password: f.password},
					auth.V3TokenOpts{Token: token},
				},
				Scope: scope.scope,
			},
		}
		want := expectationForScope(scope, []auth.AuthType{auth.AuthPassword, auth.AuthToken}, f.userID, false)
		runAuthCase(ctx, r, "v3/multifactor/password+token/"+scope.name, options, want)
	}
}

func runApplicationCredentialMatrix(ctx context.Context, r *runner, f fixtureData) {
	builders := []struct {
		name  string
		build func(bool) auth.V3ApplicationCredentialOpts
	}{
		{"id", func(reauth bool) auth.V3ApplicationCredentialOpts {
			return auth.V3ApplicationCredentialOpts{ApplicationCredentialID: f.applicationCredentialID, ApplicationCredentialSecret: f.applicationCredentialSecret, AllowReauth: reauth}
		}},
		{"name-user-id", func(reauth bool) auth.V3ApplicationCredentialOpts {
			return auth.V3ApplicationCredentialOpts{ApplicationCredentialName: f.applicationCredentialName, ApplicationCredentialSecret: f.applicationCredentialSecret, UserID: f.userID, AllowReauth: reauth}
		}},
		{"name-username-domain-id", func(reauth bool) auth.V3ApplicationCredentialOpts {
			return auth.V3ApplicationCredentialOpts{ApplicationCredentialName: f.applicationCredentialName, ApplicationCredentialSecret: f.applicationCredentialSecret, Username: f.username, UserDomainID: f.userDomainID, AllowReauth: reauth}
		}},
		{"name-username-domain-name", func(reauth bool) auth.V3ApplicationCredentialOpts {
			return auth.V3ApplicationCredentialOpts{ApplicationCredentialName: f.applicationCredentialName, ApplicationCredentialSecret: f.applicationCredentialSecret, Username: f.username, UserDomainName: f.userDomainName, AllowReauth: reauth}
		}},
	}
	for _, builder := range builders {
		for _, reauth := range []bool{false, true} {
			want := expectation{
				methods:                 []auth.AuthType{"application_credential"},
				userID:                  f.userID,
				projectID:               f.projectID,
				applicationCredentialID: f.applicationCredentialID,
				canReauth:               boolPtr(reauth),
				scoped:                  true,
			}
			options := auth.AuthOptionsV3{AuthURL: f.authURL, Auth: builder.build(reauth)}
			runAuthCase(ctx, r, fmt.Sprintf("v3/application-credential/%s/reauth=%t", builder.name, reauth), options, want)
		}
	}
}

func runOAuthMatrix(ctx context.Context, r *runner, f fixtureData) {
	for _, method := range []oauth1.SignatureMethod{oauth1.HMACSHA1, oauth1.PLAINTEXT} {
		access := f.oauthAccess[method]
		for _, reauth := range []bool{false, true} {
			options := auth.AuthOptionsV3{
				AuthURL: f.authURL,
				Auth: auth.V3OAuth1Opts{
					ConsumerKey:     f.oauthConsumerID,
					ConsumerSecret:  f.oauthConsumerSecret,
					Token:           access.OAuthToken,
					TokenSecret:     access.OAuthTokenSecret,
					SignatureMethod: auth.OAuth1SignatureMethod(method),
					AllowReauth:     reauth,
				},
			}
			want := expectation{methods: []auth.AuthType{"oauth1"}, userID: f.userID, projectID: f.projectID, canReauth: boolPtr(reauth), scoped: true}
			runAuthCase(ctx, r, fmt.Sprintf("v3/oauth1/%s/reauth=%t", strings.ToLower(string(method)), reauth), options, want)
		}
	}
}

func runCloudPasswordMatrix(ctx context.Context, r *runner, f fixtureData) {
	run := func(identity string, scope scopeCase, allowReauth, trustee bool) {
		credentials := passwordOptions(f, identity, nil, allowReauth, trustee).Auth.(auth.V3PasswordOpts)
		data, err := cloudAuthData(f.authURL, credentials, scope.scope)
		if err == nil {
			// false is omitted by the credential's JSON representation, while the
			// cloud loader defaults allow_reauth to true.
			data["allow_reauth"] = allowReauth
		}
		build := func(context.Context) (auth.Authenticator, error) {
			if err != nil {
				return nil, err
			}
			return authOptionsFromTempCloud("", auth.AuthV3Password, data)
		}
		want := expectationForScope(scope, []auth.AuthType{auth.AuthPassword}, f.userID, allowReauth)
		name := fmt.Sprintf("clouds.yaml/v3/password/%s/%s/reauth=%t", identity, scope.name, allowReauth)
		runAuthCaseBuilder(ctx, r, name, build, want)
	}

	for _, identity := range []string{"user-id", "username-domain-id", "username-domain-name"} {
		for _, allowReauth := range []bool{false, true} {
			for _, scope := range scopeCases(f)[:8] {
				run(identity, scope, allowReauth, false)
			}
			run(identity, scopeCases(f)[8], allowReauth, true)
		}
	}
}

func runCloudTokenMatrix(ctx context.Context, r *runner, f fixtureData) {
	adminToken, err := unscopedToken(ctx, f, false)
	if err != nil {
		r.run("clouds.yaml/v3/token/setup-admin-unscoped", func() error { return err })
		return
	}
	trusteeToken, err := unscopedToken(ctx, f, true)
	if err != nil {
		r.run("clouds.yaml/v3/token/setup-trustee-unscoped", func() error { return err })
		return
	}

	for _, scope := range scopeCases(f) {
		token, expectedUser := adminToken, f.userID
		if scope.trustID != "" {
			token = trusteeToken
			expectedUser = f.userID
		}
		data, dataErr := cloudAuthData(f.authURL, auth.V3TokenOpts{Token: token}, scope.scope)
		build := func(context.Context) (auth.Authenticator, error) {
			if dataErr != nil {
				return nil, dataErr
			}
			return authOptionsFromTempCloud("", auth.AuthV3Token, data)
		}
		want := expectationForScope(scope, tokenAuthMethods(), expectedUser, false)
		runAuthCaseBuilder(ctx, r, "clouds.yaml/v3/token/"+scope.name, build, want)
	}
}

func runCloudTOTPMatrix(ctx context.Context, r *runner, f fixtureData) {
	for _, identity := range []string{"user-id", "username-domain-id", "username-domain-name"} {
		for _, scope := range scopeCases(f) {
			credentials := totpOptions(f, identity, nil, "").Auth.(auth.V3TOTPOpts)
			data, dataErr := cloudAuthData(f.authURL, credentials, scope.scope)
			build := func(ctx context.Context) (auth.Authenticator, error) {
				if dataErr != nil {
					return nil, dataErr
				}
				passcode, err := freshTOTPPasscode(ctx, f.totpSecret, func() time.Time {
					return time.Now().Add(f.clockOffset)
				}, waitForContext)
				if err != nil {
					return nil, err
				}
				return authOptionsFromTempCloud("", auth.AuthV3Totp, data, auth.WithPasscode(passcode))
			}
			expectedUser := f.trusteeID
			if scope.trustID != "" {
				expectedUser = f.userID
			}
			want := expectationForScope(scope, []auth.AuthType{"totp"}, expectedUser, false)
			runAuthCaseBuilder(ctx, r, "clouds.yaml/v3/totp/"+identity+"/"+scope.name, build, want)
		}
	}
}

func runCloudMultifactorMatrix(ctx context.Context, r *runner, f fixtureData) {
	token, err := unscopedToken(ctx, f, false)
	if err != nil {
		r.run("clouds.yaml/v3/multifactor/password+token/setup-unscoped-token", func() error { return err })
		return
	}
	for _, scope := range scopeCases(f)[:8] {
		data, dataErr := cloudAuthData(f.authURL, auth.V3PasswordOpts{UserID: f.userID, Password: f.password}, scope.scope)
		if dataErr == nil {
			data["token"] = token
			data["auth_methods"] = []auth.AuthType{auth.AuthV3Password, auth.AuthV3Token}
		}
		build := func(context.Context) (auth.Authenticator, error) {
			if dataErr != nil {
				return nil, dataErr
			}
			return authOptionsFromTempCloud("", auth.AuthV3MultiFactor, data)
		}
		want := expectationForScope(scope, []auth.AuthType{auth.AuthPassword, auth.AuthToken}, f.userID, false)
		runAuthCaseBuilder(ctx, r, "clouds.yaml/v3/multifactor/password+token/"+scope.name, build, want)
	}
}

func runCloudPasswordTOTPMatrix(ctx context.Context, r *runner, f fixtureData) {
	for _, identity := range []string{"user-id", "username-domain-id", "username-domain-name"} {
		for _, scope := range scopeCases(f) {
			credentials := passwordOptions(f, identity, nil, false, true).Auth.(auth.V3PasswordOpts)
			data, dataErr := cloudAuthData(f.authURL, credentials, scope.scope)
			if dataErr == nil {
				data["auth_methods"] = []auth.AuthType{auth.AuthV3Password, auth.AuthV3Totp}
			}
			build := func(ctx context.Context) (auth.Authenticator, error) {
				if dataErr != nil {
					return nil, dataErr
				}
				passcode, err := freshTOTPPasscode(ctx, f.totpSecret, func() time.Time {
					return time.Now().Add(f.clockOffset)
				}, waitForContext)
				if err != nil {
					return nil, err
				}
				return authOptionsFromTempCloud("", auth.AuthV3MultiFactor, data, auth.WithPasscode(passcode))
			}
			expectedUser := f.trusteeID
			if scope.trustID != "" {
				expectedUser = f.userID
			}
			want := expectationForScope(scope, []auth.AuthType{auth.AuthPassword, "totp"}, expectedUser, false)
			runAuthCaseBuilder(ctx, r, "clouds.yaml/v3/multifactor/password+totp/"+identity+"/"+scope.name, build, want)
		}
	}
}

func runCloudApplicationCredentialMatrix(ctx context.Context, r *runner, f fixtureData) {
	builders := []struct {
		name  string
		build func(bool) auth.V3ApplicationCredentialOpts
	}{
		{"id", func(reauth bool) auth.V3ApplicationCredentialOpts {
			return auth.V3ApplicationCredentialOpts{ApplicationCredentialID: f.applicationCredentialID, ApplicationCredentialSecret: f.applicationCredentialSecret, AllowReauth: reauth}
		}},
		{"name-user-id", func(reauth bool) auth.V3ApplicationCredentialOpts {
			return auth.V3ApplicationCredentialOpts{ApplicationCredentialName: f.applicationCredentialName, ApplicationCredentialSecret: f.applicationCredentialSecret, UserID: f.userID, AllowReauth: reauth}
		}},
		{"name-username-domain-id", func(reauth bool) auth.V3ApplicationCredentialOpts {
			return auth.V3ApplicationCredentialOpts{ApplicationCredentialName: f.applicationCredentialName, ApplicationCredentialSecret: f.applicationCredentialSecret, Username: f.username, UserDomainID: f.userDomainID, AllowReauth: reauth}
		}},
		{"name-username-domain-name", func(reauth bool) auth.V3ApplicationCredentialOpts {
			return auth.V3ApplicationCredentialOpts{ApplicationCredentialName: f.applicationCredentialName, ApplicationCredentialSecret: f.applicationCredentialSecret, Username: f.username, UserDomainName: f.userDomainName, AllowReauth: reauth}
		}},
	}
	for _, builder := range builders {
		for _, reauth := range []bool{false, true} {
			data, dataErr := cloudAuthData(f.authURL, builder.build(reauth), nil)
			if dataErr == nil {
				data["allow_reauth"] = reauth
			}
			build := func(context.Context) (auth.Authenticator, error) {
				if dataErr != nil {
					return nil, dataErr
				}
				return authOptionsFromTempCloud("", auth.AuthV3ApplicationCredential, data)
			}
			want := expectation{
				methods:                 []auth.AuthType{"application_credential"},
				userID:                  f.userID,
				projectID:               f.projectID,
				applicationCredentialID: f.applicationCredentialID,
				canReauth:               boolPtr(reauth),
				scoped:                  true,
			}
			name := fmt.Sprintf("clouds.yaml/v3/application-credential/%s/reauth=%t", builder.name, reauth)
			runAuthCaseBuilder(ctx, r, name, build, want)
		}
	}
}

func runCloudOAuthMatrix(ctx context.Context, r *runner, f fixtureData) {
	access := f.oauthAccess[oauth1.HMACSHA1]
	for _, reauth := range []bool{false, true} {
		credentials := auth.V3OAuth1Opts{
			ConsumerKey:    f.oauthConsumerID,
			ConsumerSecret: f.oauthConsumerSecret,
			Token:          access.OAuthToken,
			TokenSecret:    access.OAuthTokenSecret,
			AllowReauth:    reauth,
		}
		data, dataErr := cloudAuthData(f.authURL, credentials, nil)
		if dataErr == nil {
			data["allow_reauth"] = reauth
		}
		build := func(context.Context) (auth.Authenticator, error) {
			if dataErr != nil {
				return nil, dataErr
			}
			return authOptionsFromTempCloud("", auth.AuthV3OAuth1, data)
		}
		want := expectation{methods: []auth.AuthType{"oauth1"}, userID: f.userID, projectID: f.projectID, canReauth: boolPtr(reauth), scoped: true}
		runAuthCaseBuilder(ctx, r, fmt.Sprintf("clouds.yaml/v3/oauth1/hmac-sha1/reauth=%t", reauth), build, want)
	}
}

type noAuthCase struct {
	name              string
	opts              auth.NoAuthOpts
	endpointProjectID string
}

func noAuthCases(f fixtureData) []noAuthCase {
	return []noAuthCase{
		{
			name:              "explicit-project",
			opts:              auth.NoAuthV3Opts{UserID: f.userID, ProjectID: f.projectID},
			endpointProjectID: f.projectID,
		},
		{
			name:              "project-defaulted",
			opts:              auth.NoAuthV3Opts{UserID: f.userID},
			endpointProjectID: f.userID,
		},
	}
}

func runNoAuthMatrix(ctx context.Context, r *runner, f fixtureData) {
	endpoint, err := cinderNoAuthEndpoint(f.authURL, 3)
	if err != nil {
		r.run("service/noauth/cinder-v3/endpoint", func() error { return err })
		return
	}
	for _, test := range noAuthCases(f) {
		r.run("service/noauth/cinder-v3/"+test.name, func() error {
			provider, err := blockstoragenoauth.NewClient(test.opts)
			if err != nil {
				return err
			}
			if provider.TokenID == "" {
				return errors.New("no-auth provider has an empty token")
			}
			service, err := blockstoragenoauth.NewBlockStorageNoAuthV3(provider, blockstoragenoauth.EndpointOpts{
				CinderEndpoint: endpoint,
			})
			if err != nil {
				return err
			}
			wantEndpoint := gophercloud.NormalizeURL(gophercloud.NormalizeURL(endpoint) + test.endpointProjectID)
			if service.Endpoint != wantEndpoint {
				return fmt.Errorf("service endpoint = %q, want %q", service.Endpoint, wantEndpoint)
			}
			_, err = service.Get(ctx, service.ServiceURL("volumes", "detail"), nil, &gophercloud.RequestOpts{OkCodes: []int{200, 204}})
			return err
		})
	}
}

func runNoAuthV2(ctx context.Context, r *runner, authURL string, password auth.V2PasswordOpts) {
	endpoint, err := cinderNoAuthEndpoint(authURL, 2)
	if err != nil {
		r.run("service/noauth/cinder-v2/endpoint", func() error { return err })
		return
	}

	r.run("service/noauth/cinder-v2", func() error {
		provider, err := blockstoragenoauth.NewClient(auth.NoAuthV2Opts{
			Username:   password.Username,
			TenantName: password.TenantName,
		})
		if err != nil {
			return err
		}
		service, err := blockstoragenoauth.NewBlockStorageNoAuthV2(provider, blockstoragenoauth.EndpointOpts{
			CinderEndpoint: endpoint,
		})
		if err != nil {
			return err
		}
		_, err = service.Get(ctx, service.ServiceURL("volumes", "detail"), nil, &gophercloud.RequestOpts{OkCodes: []int{200, 204}})
		return err
	})
}

func runEC2AuthCase(ctx context.Context, r *runner, serviceProvider *gophercloud.ProviderClient, name string, options auth.AuthOptionsEC2, want expectation) {
	options.ServiceProvider = serviceProvider

	r.run(name+"/AuthResult", func() error {
		result, err := options.Authenticate(ctx, nil)
		if err != nil {
			return err
		}
		return validateAuthResult(result, want)
	})

	r.run(name+"/ProviderClient", func() error {
		provider, err := openstack.AuthenticatedClient(ctx, options)
		if err != nil {
			return err
		}
		result, ok := provider.GetAuthResult().(*auth.AuthResult)
		if !ok {
			return fmt.Errorf("ProviderClient auth result has type %T", provider.GetAuthResult())
		}
		if err := validateAuthResult(result, want); err != nil {
			return err
		}
		if want.canReauth != nil && *want.canReauth {
			if provider.ReauthFunc == nil {
				return errors.New("reauthentication requested but ReauthFunc is nil")
			}
			if err := provider.ReauthFunc(ctx); err != nil {
				return fmt.Errorf("reauthentication failed: %w", err)
			}
		} else if provider.ReauthFunc != nil {
			return errors.New("unexpected ReauthFunc")
		}
		return nil
	})
}

type ec2Case struct {
	name string
	opts auth.EC2TokenOpts
}

func supportedEC2Cases(f fixtureData) []ec2Case {
	return []ec2Case{
		{name: "v4-default", opts: auth.EC2TokenOpts{Access: f.ec2Access, Secret: f.ec2Secret}},
		{name: "v2-hmac-sha256", opts: auth.EC2TokenOpts{Access: f.ec2Access, Secret: f.ec2Secret, Host: "localhost", Path: "/", Verb: "GET", Params: map[string]string{"Action": "Test", "SignatureMethod": auth.EC2CredentialsHmacSha256V2, "SignatureVersion": "2"}}},
	}
}

func runEC2Matrix(ctx context.Context, r *runner, f fixtureData, serviceProvider *gophercloud.ProviderClient) {
	for _, builder := range supportedEC2Cases(f) {
		for _, reauth := range []bool{false, true} {
			opts := builder.opts
			opts.AllowReauth = reauth
			options := auth.AuthOptionsEC2{AuthURL: f.authURL, Auth: opts}
			want := expectation{methods: []auth.AuthType{"ec2credential"}, userID: f.userID, projectID: f.projectID, canReauth: boolPtr(reauth), scoped: true}
			runEC2AuthCase(ctx, r, serviceProvider, fmt.Sprintf("v3/ec2/%s/reauth=%t", builder.name, reauth), options, want)
		}
	}
}

func runV2WithOptions(ctx context.Context, options auth.AuthOptionsV2) int {
	r := newRunner()

	password, ok := options.Auth.(auth.V2PasswordOpts)
	if !ok {
		r.run("setup/v2-password-environment", func() error {
			return fmt.Errorf("v2 environment produced %T, want auth.V2PasswordOpts", options.Auth)
		})
		r.summary()
		return r.exitCode()
	}

	initial, err := options.Authenticate(ctx, nil)
	if err != nil {
		r.run("setup/v2-token", func() error { return err })
		r.summary()
		return r.exitCode()
	}
	if initial.Project == nil {
		r.run("setup/v2-token", func() error { return errors.New("v2 password token is not tenant-scoped") })
		r.summary()
		return r.exitCode()
	}

	wantPassword := expectation{
		userID:    initial.User.ID,
		projectID: initial.Project.ID,
		canReauth: boolPtr(password.AllowReauth),
		scoped:    true,
	}
	runAuthCase(ctx, r, "v2/password", options, wantPassword)

	tokenOptions := auth.AuthOptionsV2{
		AuthURL: options.AuthURL,
		Auth: auth.V2TokenOpts{
			Token:       initial.TokenID,
			TenantID:    initial.Project.ID,
			TenantName:  initial.Project.Name,
			AllowReauth: true,
		},
	}
	wantToken := expectation{
		userID:    initial.User.ID,
		projectID: initial.Project.ID,
		canReauth: boolPtr(true),
		scoped:    true,
	}
	runAuthCase(ctx, r, "v2/token", tokenOptions, wantToken)
	runNoAuthV2(ctx, r, options.AuthURL, password)

	r.summary()
	return r.exitCode()
}

func runV2() int {
	options, err := auth.AuthOptionsFromEnvV2()
	if err != nil {
		r := newRunner()
		r.run("setup/v2-environment", func() error { return err })
		r.summary()
		return r.exitCode()
	}
	return runV2WithOptions(context.Background(), options)
}

func runV3() int {
	ctx := context.Background()
	r := newRunner()

	f, identity, cleanup, err := setupFixtures(ctx)
	if err != nil {
		r.run("setup/temporary-auth-resources", func() error { return err })
		for _, cleanupErr := range cleanup() {
			r.run("cleanup/after-failed-setup", func() error { return cleanupErr })
		}
		r.summary()
		return r.exitCode()
	}

	runPasswordMatrix(ctx, r, f)
	runTokenAndRescopeMatrix(ctx, r, f)
	runMultifactorMatrix(ctx, r, f)
	runTOTPMatrix(ctx, r, f)
	runCloudPasswordMatrix(ctx, r, f)
	runCloudTokenMatrix(ctx, r, f)
	runCloudMultifactorMatrix(ctx, r, f)
	runCloudTOTPMatrix(ctx, r, f)

	runPasswordTOTPMatrix(ctx, r, f, identity)
	runApplicationCredentialMatrix(ctx, r, f)
	runOAuthMatrix(ctx, r, f)
	runEC2Matrix(ctx, r, f, identity.ProviderClient)
	runNoAuthMatrix(ctx, r, f)

	runCloudPasswordTOTPMatrix(ctx, r, f)
	runCloudApplicationCredentialMatrix(ctx, r, f)
	runCloudOAuthMatrix(ctx, r, f)

	r.skip("v2/password", "Keystone v2 is not exposed by this DevStack")
	r.skip("v2/token", "Keystone v2 is not exposed by this DevStack")
	r.skip("v3/ec2/v2-hmac-sha1", "Keystone uses HMAC-SHA1 only when HMAC-SHA256 is unavailable")
	r.skip("service/noauth/cinder-v2", "this Cinder deployment exposes only the v3 API")

	for i, cleanupErr := range cleanup() {
		err := cleanupErr
		r.run(fmt.Sprintf("cleanup/%d", i+1), func() error { return err })
	}
	r.summary()
	return r.exitCode()
}

func runSelected(args []string, stderr io.Writer, runners map[string]func() int) int {
	flags := flag.NewFlagSet("client", flag.ContinueOnError)
	flags.SetOutput(stderr)
	version := flags.String("version", "", "identity API version to test (2 or 3)")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	run, ok := runners[*version]
	if !ok {
		fmt.Fprintln(stderr, "-version must be 2 or 3")
		flags.Usage()
		return 2
	}
	return run()
}

func main() {
	os.Exit(runSelected(os.Args[1:], os.Stderr, map[string]func() int{
		"2": runV2,
		"3": runV3,
	}))
}
