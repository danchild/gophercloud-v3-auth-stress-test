# Gophercloud Keystone Auth Stress Test

The following script in `main.go` provides a way to test a relatively
exhaustive list of `AuthOptions` permutations againt the proposed
gophercloud v3 `auth` package. 

### Usage

Source the default admin OpenRC from your DevStack environment, then run the
client from this directory:

```sh
# Against keystone v3
source ./admin-openrc-v3.sh
go run . -version 3

# Against keystone v2
source ./admin-openrc-v2.sh
go run . -version 2
```

For an HTTPS Keystone endpoint signed by a private CA, pass the optional
`-cacert` flag with a PEM CA certificate. It applies to direct authentication,
provider-based authentication, reauthentication, and raw HTTP requests in this
process. Without the flag, the normal system trust store is used; certificate
verification is never disabled. For example, to test the DevStack HTTPS proxy:

```sh
source admin-openrc-v3.sh
export OS_AUTH_URL=https://10.0.78.90/identity/
go run . -version 3 -cacert ./devstack-ca.pem
```

`devstack-ca.pem` contains only the public CA certificate for this test server,
not the server's private key. Replace it if the DevStack CA is rotated (current
certificate expires in November 2027).

For the full v3 matrix behind a TLS-terminating proxy, Keystone must also
advertise an HTTPS `public_endpoint`: OAuth1 HMAC signatures include the URL
scheme. A CA certificate alone does not change the server's endpoint setting.

`main.go` reads the admin credentials from the `OS_*` environment variables.
The `clouds.yaml` cases create temporary files inline using those credentials
and test credentials derived from the `env` vars, so you do not need to supply one.
Both versions test generic `password` and `token` auth through `OS_*` and
`clouds.yaml`, including identity version selection. The v2 generic cases use
the versioned `/v2.0/` endpoint derived from the admin auth URL and temporarily
unset `OS_IDENTITY_API_VERSION`; a versionless endpoint that advertises stable
v3 and deprecated v2 would otherwise select v3. For HTTPS with `-cacert`,
the generic environment cases set `OS_CACERT` while loading auth options, and
the generated YAML entries contain `cacert`; its parsed TLS configuration is
used for both discovery and authentication. Run v3 once with HTTPS and
`-cacert`, once with HTTP, and run v2 with HTTP to cover all three modes.
The token cases use a token issued from password credentials, not `OS_TOKEN`.
The v3 run creates temporary Keystone resources and cleans
them up; the admin account needs permission to create users, assign roles,
and create trusts and credentials.

Combinations of the following options are used in the coverage.
The runner also constructs complete JSON bodies and signatures independently of
`auth` request builders, then submits them through the raw identity endpoint
APIs: v2 `tokens.Create` (`-version 2`) and v3 `tokens.Create`,
`oauth1.Create` (PLAINTEXT), and `ec2tokens.Create` (AWS signature v2)
(`-version 3`). Run `go test ./...` to exercise these requests against a local
HTTP test server without Keystone credentials.

### Keystone v3 (`-version 3`)

- **Auth options**:
  - `V3PasswordOpts`
  - `V3TokenOpts` (including an unscoped token with a new `Scope`)
  - `V3TOTPOpts`
  - `V3ApplicationCredentialOpts`:
    - `ApplicationCredentialID` + `ApplicationCredentialSecret`
    - `ApplicationCredentialName` + `ApplicationCredentialSecret` + `UserID`
    - `ApplicationCredentialName` + `ApplicationCredentialSecret` + `Username` + `UserDomainID`
    - `ApplicationCredentialName` + `ApplicationCredentialSecret` + `Username` + `UserDomainName`
  - `V3OAuth1Opts`
  - `EC2TokenOpts`
- **Multifactor** (`V3MultifactorOpts.AuthMethods`):
  - `V3PasswordOpts` + `V3TokenOpts`: all scopes except `TrustID`
  - `V3PasswordOpts` + `V3TOTPOpts`: all scopes
- **User**:
  - `UserID`
  - `Username` + `UserDomainID`
  - `Username` + `UserDomainName`
- **Scope**:
  - `nil` or `&Scope{}`
  - `ProjectID`
  - `ProjectName` + `ProjectDomainID`
  - `ProjectName` + `ProjectDomainName`
  - `DomainID`
  - `DomainName`
  - `System: true`
  - `TrustID`
- **Reauth** (`AllowReauth`):
  - `false` or `true`: `V3PasswordOpts`, `V3ApplicationCredentialOpts`, `V3OAuth1Opts`, `EC2TokenOpts`
- **Signatures**:
  - `V3OAuth1Opts.SignatureMethod`: `OAuth1HMACSHA1` or `OAuth1Plaintext` (cloud: `OAuth1HMACSHA1` only)
  - `EC2TokenOpts`: default v4 or v2 with `EC2CredentialsHmacSha256V2`
- **Cinder no-auth** (`NoAuthV3Opts`):
  - `UserID` + `ProjectID`
  - `UserID` only

### Keystone v2 (`-version 2`)

- `AuthOptionsV2` + `V2PasswordOpts`
- `AuthOptionsV2` + `V2TokenOpts`
- Cinder no-auth: `NoAuthV2Opts{Username, TenantName}`
