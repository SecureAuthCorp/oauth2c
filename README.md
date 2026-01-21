# OAuth2c: user-friendly OAuth CLI

[![status](https://github.com/cloudentity/oauth2c/workflows/build/badge.svg)](https://github.com/cloudentity/oauthc/actions)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0.html)
[![release](https://img.shields.io/github/release-pre/cloudentity/oauth2c.svg)](https://github.com/cloudentity/oauth2c/releases)
[![downloads](https://img.shields.io/github/downloads/cloudentity/oauth2c/total)](https://github.com/cloudentity/oauth2c/releases)
[![packages](https://repology.org/badge/tiny-repos/oauth2c.svg)](https://repology.org/project/oauth2c/versions)

`oauth2c` is a command-line tool for interacting with OAuth 2.0 authorization
servers. Its goal is to make it easy to fetch access tokens using any grant type
or client authentication method. It is compliant with almost all basic and
advanced OAuth 2.0, OIDC, OIDF FAPI and JWT profiles.

![demo](https://user-images.githubusercontent.com/909896/176916616-36d803ef-832a-4bd8-ba8d-f6689e31ed22.gif)

## Features

- support for **authorization code**, **hybrid**, **implicit**, **password**,
  **client credentials**, **refresh token**, **JWT bearer**, **token exchange**,
  **device** grant flows
- support for **client secret basic**, **client secret post**, **client secret
  JWT**, **private key JWT**, **TLS client auth** client authentication methods
- passing request parameters as plaintext, signed, and/or encrypted JWT
- support for **Proof Key for Code Exchange** (**PKCE**)
- support for **JWT Secured Authorization Response Mode** (**JARM**)
- support for **Pushed Authorization Requests** (**PAR**)
- support for **Demonstration of Proof of Possession** (**DPoP**)
- support for **Rich Authorization Requests** (**RAR**)

## Installation

<a href="https://repology.org/project/oauth2c/versions">
    <img src="https://repology.org/badge/vertical-allrepos/oauth2c.svg" alt="Packaging status" align="right">
</a>

To install `oauth2c`, you have several options depending on your operating
system.

### Install on Mac

On Mac, you can install `oauth2c` using `brew` by running the following command:

```sh
brew install cloudentity/tap/oauth2c
```

### Install on Linux

On linux, you can install `oauth2c` using the installation script by running the
following command:

```sh
curl -sSfL https://raw.githubusercontent.com/cloudentity/oauth2c/master/install.sh | \
  sudo sh -s -- -b /usr/local/bin latest
```

Alternatively, you can check the [packages page] for specific instructions on
installing oauth2c using a package manager.

[packages page]: https://repology.org/project/oauth2c/versions

### Compile from source

To compile `oauth2c` from source using `go`. To do this run the following
command:

```sh
go install github.com/cloudentity/oauth2c@latest
```

You can also download a pre-built binary from the [releases page].

[releases page]: https://github.com/cloudentity/oauth2c/releases

## Usage

To use `oauth2c`, run the following command and follow the prompts:

```sh
oauth2c [issuer url] [flags]
```

The available flags are:

```sh
      --acr-values strings                                  ACR values
      --actor-token string                                  acting party token
      --actor-token-type string                             acting party token type
      --assertion string                                    claims for jwt bearer assertion
      --audience strings                                    requested audience
      --auth-method string                                  token endpoint authentication method
      --authentication-code string                          authentication code used for passwordless authentication
      --authorization-endpoint string                       server's authorization endpoint
      --browser-timeout duration                            browser timeout (default 10m0s)
      --callback-addr string                                callback server bind address (e.g., 0.0.0.0:8080)
      --callback-tls-cert string                            path to callback tls cert pem file
      --callback-tls-key string                             path to callback tls key pem file
      --claims string                                       use claims
      --client-id string                                    client identifier
      --client-secret string                                client secret
      --device-authorization-endpoint string                server's device authorization endpoint
      --dpop                                                use DPoP
      --encrypted-request-object                            pass request parameters as encrypted jwt
      --encryption-key string                               path or url to encryption key in jwks format
      --grant-type string                                   grant type
  -h, --help                                                help for oauth2c
      --http-timeout duration                               http client timeout (default 1m0s)
      --id-token-hint string                                id token hint
      --idp-hint string                                     identity provider hint
      --insecure                                            allow insecure connections
      --login-hint string                                   user identifier hint
      --max-age string                                      maximum authentication age in seconds
      --mtls-pushed-authorization-request-endpoint string   server's mtls pushed authorization request endpoint
      --mtls-token-endpoint string                          server's mtls token endpoint
      --no-browser                                          do not open browser
      --no-prompt                                           disable prompt
      --par                                                 enable pushed authorization requests (PAR)
      --password string                                     resource owner password credentials grant flow password
      --pkce                                                enable proof key for code exchange (PKCE)
      --prompt strings                                      end-user authorization purpose
      --purpose string                                      string describing the purpose for obtaining End-User authorization
      --pushed-authorization-request-endpoint string        server's pushed authorization request endpoint
      --rar string                                          use rich authorization request (RAR)
      --redirect-url string                                 client redirect url (default "http://localhost:9876/callback")
      --refresh-token string                                refresh token
      --request-object                                      pass request parameters as jwt
      --response-mode string                                response mode
      --response-types strings                              response type
      --scopes strings                                      requested scopes
      --signing-key string                                  path or url to signing key in jwks format
  -s, --silent                                              silent mode
      --subject-token string                                third party token
      --subject-token-type string                           third party token type
      --tls-cert string                                     path to tls cert pem file
      --tls-key string                                      path to tls key pem file
      --tls-root-ca string                                  path to tls root ca pem file
      --token-endpoint string                               server's token endpoint
      --username string                                     resource owner password credentials grant flow username
```

`oauth2c` opens a browser for flows such as authorization code and starts an
HTTP server which acts as a client application and waits for a callback.

> **Note**: To make browser flows work add `http://localhost:9876/callback` as a
> redirect URL to your client.

`oauth2c` prints all the requests it made to obtain an access token. If you want
to integrate it with CI/CD pipeline use the `--silent` flag.

For more information on the available options and arguments run
`oauth2c --help`.

## Examples

Here are a few examples of using oauth2c with different grant types and client
authentication methods:

### Grant types

> **NOTE**: The authorization code, implicit, hybrid and device grant flows
> require browser and user authentication.

#### Authorization code

This grant type involves a two-step process where the user first grants
permission to access their data, and then the client exchanges the authorization
code for an access token. This grant type is typically used in server-side
applications.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic
```

[Learn more about authorization code flow](https://cloudentity.com/developers/basics/oauth-grant-types/authorization-code-flow/)

#### Implicit

This grant type is similar to the authorization code grant, but the access token
is returned directly to the client without an intermediate authorization code.
This grant type is typically used in single-page or mobile applications.

> **Note**: The implicit flow is not recommended for use in modern OAuth2
> applications. Instead, it is recommended to use the authorization code flow
> with PKCE (Proof Key for Code Exchange) for added security.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --response-types token \
  --response-mode form_post \
  --grant-type implicit \
  --scopes openid,email,offline_access
```

[Learn more about implicit flow](https://cloudentity.com/developers/basics/oauth-grant-types/implicit-flow/)

#### Hybrid

To use the OAuth2 hybrid flow to obtain an authorization code and an ID token,
the client first sends an authorization request to the OAuth2 provider. The
request should include the code and id_token response types.

The OAuth2 provider will then return an authorization code and an ID token to
the client, either in the response body or as fragment parameters in the
redirect URL, depending on the response mode specified in the request. The
client can then use the authorization code to obtain an access token by sending
a token request to the OAuth2 provider.

The ID token can be used to verify the identity of the authenticated user, as it
contains information such as the user's name and email address. The ID token is
typically signed by the OAuth2 provider, so the client can verify its
authenticity using the provider's public key.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code,id_token \
  --response-mode form_post \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access
```

[Learn more about the hybrid flow](https://cloudentity.com/developers/basics/oauth-grant-types/hybrid-flow/)

#### Client credentials

This grant type involves the client providing its own credentials to the OAuth2
server, which then returns an access token. This grant type is typically used
for server-to-server communication, where the client is a trusted server rather
than a user.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about the client credentials flow](https://cloudentity.com/developers/basics/oauth-grant-types/client-credentials-flow/)

### Refresh token

This grant type involves the client providing a refresh token to the OAuth2
server, which then returns a new access token.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type refresh_token\
  --auth-method client_secret_basic \
  --refresh-token $REFRESH_TOKEN
```

> **Note** In order to use this command, you must first set the REFRESH_TOKEN
> environment variable
>
> <details>
> <summary>Show example</summary>
>
> ```sh
> export REFRESH_TOKEN=`oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
>   --client-id cauktionbud6q8ftlqq0 \
>   --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
>   --response-types code \
>   --response-mode query \
>   --grant-type authorization_code \
>   --auth-method client_secret_basic \
>   --scopes openid,email,offline_access \
>   --silent | jq -r .refresh_token`
> ```
>
> </details>

[Learn more about the refresh token flow](https://cloudentity.com/developers/basics/oauth-grant-types/refresh-token-flow/)

#### Password

This grant type involves the client providing the user's username and password
to the OAuth2 server, which then returns an access token. This grant type should
only be used in secure environments, as it involves sending the user's
credentials to the OAuth2 server.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type password \
  --username demo \
  --password demo \
  --auth-method client_secret_basic \
  --scopes openid
```

[Learn more about the password flow](https://cloudentity.com/developers/basics/oauth-grant-types/resource-owner-password-credentials/)

#### Device

This grant type is a two-step process that allows a user to grant access to
their data without having to enter a username and password. In the first step,
the user grants permission for the client to access their data. In the second
step, the client exchanges the authorization code received in the first step for
an access token. This grant type is commonly used in server-side applications,
such as when accessing a device from a TV or other non-interactive device.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type urn:ietf:params:oauth:grant-type:device_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access
```

[Learn more about the device flow](https://cloudentity.com/developers/basics/oauth-grant-types/device/)

#### JWT Bearer

This grant type involves the client providing a JSON Web Token (JWT) to the
OAuth2 server, which then returns an access token. This grant type is typically
used when the client is a trusted third-party, such as a JWT issuer.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type urn:ietf:params:oauth:grant-type:jwt-bearer \
  --auth-method client_secret_basic \
  --scopes email \
  --signing-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/rsa/key.json \
  --assertion '{"sub":"jdoe@example.com"}'
```

[Learn more about the jwt bearer flow](https://cloudentity.com/developers/basics/oauth-grant-types/using-jwt-profile-for-authorization-flows/)

#### Token exchange

The token exchange OAuth2 grant flow involves the client providing an access
token to the OAuth2 server, which then returns a new access token. This grant
type is typically used when the client and the OAuth2 server have a pre-existing
trust relationship, such as when the client is a trusted third-party.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type urn:ietf:params:oauth:grant-type:token-exchange \
  --auth-method client_secret_basic \
  --scopes email \
  --subject-token $SUBJECT_TOKEN \
  --subject-token-type urn:ietf:params:oauth:token-type:access_token \
  --actor-token $ACTOR_TOKEN \
  --actor-token-type urn:ietf:params:oauth:token-type:access_token
```

> **Note** In order to use this command, you must first set the SUBJECT_TOKEN
> and ACTOR_TOKEN environment variables
>
> <details>
> <summary>Show example</summary>
>
> ```sh
> export SUBJECT_TOKEN=`oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
>   --client-id cauktionbud6q8ftlqq0 \
>   --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
>   --response-types code \
>   --response-mode query \
>   --grant-type authorization_code \
>   --auth-method client_secret_basic \
>   --scopes openid,email,offline_access \
>   --silent | jq -r .access_token`
> ```
>
> ```sh
> export ACTOR_TOKEN=`oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
>   --client-id cauktionbud6q8ftlqq0 \
>   --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
>   --grant-type client_credentials \
>   --auth-method client_secret_basic \
>   --scopes introspect_tokens,revoke_tokens \
>   --silent | jq -r .access_token`
> ```
>
> </details>

[Learn more about the token exchange flow](https://cloudentity.com/developers/basics/oauth-grant-types/token-exchange/)

### Auth methods

#### Client Secret Basic

This client authentication method involves the client sending its credentials as
part of the HTTP Basic authentication header in the request to the OAuth2
server. This method is simple and widely supported, but it is less secure than
other methods because the client secret is sent in the clear.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --grant-type client_credentials \
  --auth-method client_secret_basic \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about client secret basic](https://cloudentity.com/developers/basics/oauth-client-authentication/client-secret-authentication/#process-of-authentication-with-client_secret_basic)

#### Client Secret Post

This client authentication method involves the client sending its credentials as
part of the request body in the request to the OAuth2 server. This method
provides more security than the basic authentication method, but it requires the
request to be sent via HTTPS to prevent the client secret from being
intercepted.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauosoo2omc4fr8ai1fg \
  --client-secret ipFkA1lMomOMI_d2HcGGQ7j8oxeHFqKw3kli76g92VM \
  --grant-type client_credentials \
  --auth-method client_secret_post \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about client secret post](https://cloudentity.com/developers/basics/oauth-client-authentication/client-secret-authentication/#process-of-authentication-with-client_secret_post)

#### Client Secret JWT

This client authentication method involves the client signing a JSON Web Token
(JWT) using its client secret, and then sending the JWT to the OAuth2 server.
This method provides a higher level of security than the basic or post methods,
as the client secret is never sent in the clear.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id ab966ce4f2ac4f4aa641582b099c32d3 \
  --client-secret 578-WfFYfBheWb8gJpHYXMRRqR5HN0qv7d7xIolJnIE \
  --grant-type client_credentials \
  --auth-method client_secret_jwt \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about client secret jwt](https://cloudentity.com/developers/basics/oauth-client-authentication/client-secret-authentication/#process-of-authentication-with-client_secret_jwt)

#### Private Key JWT

This client authentication method involves the client signing a JSON Web Token
(JWT) using its private key, and then sending the JWT to the OAuth2 server. This
method provides a higher level of security than the JWT methods using a client
secret, as the private key is never shared with the OAuth2 server.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id 582af0afb0d74554aa7af47849edb222 \
  --signing-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/rsa/key.json \
  --grant-type client_credentials \
  --auth-method private_key_jwt \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about private key jwt](https://cloudentity.com/developers/basics/oauth-client-authentication/private-key-jwt-client-authentication/)

#### TLS Client Auth

This client authentication method involves the client providing its own
certificate as part of the TLS handshake when connecting to the OAuth2 server.
This method provides a high level of security, as the client's identity is
verified using a trusted certificate authority. However, it requires the OAuth2
server to support TLS client authentication, which may not be supported by all
OAuth2 providers.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id 3f07a8c2adea4c1ab353f3ca8e16b8fd \
  --tls-cert https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/cert.pem \
  --tls-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/key.pem \
  --grant-type client_credentials \
  --auth-method tls_client_auth \
  --scopes introspect_tokens,revoke_tokens
```

[Learn more about tls client auth](https://cloudentity.com/developers/basics/oauth-client-authentication/oauth-mtls-client-authentication/)

#### None with PKCE

Public clients, such as mobile apps, are unable to authenticate themselves to
the authorization server in the same way that confidential clients can because
they do not have a client secret. To protect themselves from having their
authorization codes intercepted and used by attackers, public clients can use
PKCE (Proof Key for Code Exchange) during the authorization process. PKCE
provides an additional layer of security by ensuring that the authorization code
can only be exchanged for a token by the same client that initially requested
it. This helps prevent unauthorized access to the token.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id db5e375e7b634095b24bbb683fcb955b \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method none \
  --scopes openid,email \
  --pkce
```

[Lean more about none with PKCE](https://cloudentity.com/developers/basics/oauth-client-authentication/client-auth-set-to-none-with-pkce/)

### Extensions

#### Request Object

The Request Object is a JWT that contains the parameters of an authorization
request. It allows the request to be passed along as a single, self-contained
parameter, and it can be optionally signed and/or encrypted for added security.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --request-object
```

#### Request claims

Requesting Claims using the "claims" Request Parameter enables clients to
request specific user attributes in an authorization, enhancing efficiency and
security.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,offline_access \
  --claims '{"id_token":{"email": {"essential": true}}}'
```

#### PKCE

The Proof Key for Code Exchange (PKCE) is an extension to the OAuth2
authorization code grant flow that provides additional security when
authenticating with an OAuth2 provider. In the PKCE flow, the client generates a
code verifier and a code challenge, which are then sent to the OAuth2 provider
during the authorization request. The provider returns an authorization code,
which the client then exchanges for an access token along with the code
verifier. The provider verifies the code verifier to ensure that the request is
coming from the same client that initiated the authorization request.

This additional step helps to prevent attackers from intercepting the
authorization code and using it to obtain an access token. PKCE is recommended
for all public clients, such as single-page or mobile applications, where the
client secret cannot be securely stored.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id db5e375e7b634095b24bbb683fcb955b \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method none \
  --scopes openid,email \
  --pkce
```

[Learn more about authorization code flow with pkce](https://cloudentity.com/developers/basics/oauth-grant-types/authorization-code-with-pkce/)

#### JARM

JWT-secured OAuth 2.0 authorization response, also known as JARM, is a method of
securely transmitting authorization information in an OAuth 2.0 authorization
response using JSON Web Tokens (JWT). This allows the authorization response to
be verified by the client, ensuring that the information is coming from a
trusted source and has not been tampered with. The JWT is signed using a secret
key shared between the authorization server and the client, allowing the client
to verify the authenticity of the JWT. This provides an additional layer of
security to the OAuth 2.0 authorization process.

**Signed JWT**

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query.jwt \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access
```

**Signed and encrypted JWT**

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauosoo2omc4fr8ai1fg \
  --client-secret ipFkA1lMomOMI_d2HcGGQ7j8oxeHFqKw3kli76g92VM \
  --response-types code \
  --response-mode query.jwt \
  --grant-type authorization_code \
  --auth-method client_secret_post \
  --scopes openid,email,offline_access \
  --encryption-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/rsa/key.json
```

#### PAR

Pushed Authorization Requests (PAR) is an extension of the OAuth 2.0
specification that enables client applications to push the payloads of
authorization requests directly to the authorization server via a PAR endpoint.
This allows for more efficient and secure handling of authorization requests.
PAR can be useful for client applications that require a high level of security,
and may be required for compliance with certain security profiles and
regulations.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --par
```

[Learn more about PAR](https://cloudentity.com/developers/basics/oauth-grant-types/pushed-authorization-requests/)

#### DPoP

DPoP, or Demonstration of Proof of Possession, is an extension that describes a
technique to cryptographically bind access tokens to a particular client when
they are issued. This is one of many attempts at improving the security of
Bearer Tokens by requiring the application using the token to authenticate
itself.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --scopes openid,email,offline_access \
  --signing-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/ps/key.json \
  --dpop
```

#### RAR

[Rich Authorization Request (RAR)](https://datatracker.ietf.org/doc/html/rfc9396)
introduces a new parameter `authorization_details` that allows clients to
specify their fine-grained authorization requirements using the expressiveness
of JSON data structures. For example, an authorization request for a credit
transfer (designated as "payment initiation" in several open banking
initiatives) can be represented using a JSON object like this:

```
{
   "type": "payment_initiation",
   "locations": [
      "https://example.com/payments"
   ],
   "instructedAmount": {
      "currency": "EUR",
      "amount": "123.50"
   },
   "creditorName": "Merchant A",
   "creditorAccount": {
      "bic":"ABCIDEFFXXX",
      "iban": "DE02100100109307118603"
   },
   "remittanceInformationUnstructured": "Ref Number Merchant"
}
```

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --rar '[{"type":"payment_initiation","locations":["https://example.com/payments"],"instructedAmount":{"currency":"EUR","amount":"123.50"},"creditorName":"Merchant A","creditorAccount":{"bic":"ABCIDEFFXXX","iban":"DE02100100109307118603"},"remittanceInformationUnstructured":"Ref Number Merchant"}]'
```

### Miscellaneous

#### Using HTTPs for Callback URL

You can use `--callback-tls-cert` and `--callback-tls-key` flags to specify a
TLS certificate and key for the HTTPs callback redirect URL.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --redirect-url https://localhost:9876/callback \
  --callback-tls-cert https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/cert.pem \
  --callback-tls-key https://raw.githubusercontent.com/cloudentity/oauth2c/master/data/key.pem
```

#### Using a TLS-Terminating Proxy

When running behind a TLS-terminating proxy (e.g., nginx, Traefik, or a cloud
load balancer), use `--callback-addr` to specify the local bind address while
keeping the public HTTPS URL in `--redirect-url`.

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --redirect-url https://example.com/callback \
  --callback-addr 0.0.0.0:8080
```

In this configuration:
- `--redirect-url` is the public URL sent to the IdP in the OAuth request
- `--callback-addr` is the local address where the callback server binds
- The callback server serves HTTP (no TLS certs provided), while the proxy handles TLS termination

#### Specifying Authorization Server's Endpoint Manually

If your authorization server does not support OIDC, you can specify the endpoint manually using flags. 

```sh
oauth2c https://oauth2c.us.authz.cloudentity.io/oauth2c/demo \
  --client-id cauktionbud6q8ftlqq0 \
  --client-secret HCwQ5uuUWBRHd04ivjX5Kl0Rz8zxMOekeLtqzki0GPc \
  --response-types code \
  --response-mode query \
  --grant-type authorization_code \
  --auth-method client_secret_basic \
  --token-endpoint https://oauth2c.us.authz.cloudentity.io/oauth2c/demo/oauth2/token \
  --authorization-endpoint https://oauth2c.us.authz.cloudentity.io/oauth2c/demo/oauth2/authorize
```

## License

`oauth2c` is released under the
[Apache v2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Contributing

We welcome contributions! If you have an idea for a new feature or have found a
bug, please open an issue on GitHub.
