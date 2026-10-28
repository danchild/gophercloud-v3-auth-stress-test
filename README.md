# Gophercloud Keystone Auth Stress Test

The following script in `main.go` provides a way to test a relatively
exhaustive list of `AuthOptions` permutations againt the proposed
gophercloud v3 `auth` package. 

### Usage

Source the default admin OpenRC from your DevStack environment, then run the
client from this directory:

```sh
# Against keystone v3
source ./admin-openrc.sh 
go run main.go -version 3

# Against keystone v2
source ./admin-openrc.sh 
go run main.go -version 2
```

`main.go` reads the admin credentials from the `OS_*` environment variables.
The `clouds.yaml` cases create temporary files inline using those credentials
and test credentials derived from the `env` vars, so you do not need to supply one.
The v3 run creates temporary Keystone resources and cleans
them up; the admin account needs permission to create users, assign roles,
and create trusts and credentials.

Combinations of the following options are used in the coverage:

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
