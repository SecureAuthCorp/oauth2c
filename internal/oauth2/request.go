package oauth2

import (
	"crypto/sha256"
	"crypto/x509"
	"net/http"
	"net/url"
	"strings"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/go-multierror"
	"github.com/lithammer/shortuuid/v4"
	"github.com/pkg/errors"
)

type Request struct {
	Method        string
	URL           *url.URL
	Headers       map[string][]string
	Form          url.Values
	JARM          map[string]interface{}
	RequestObject string
	SigningKey    interface{}
	// The client assertion is signed independently of the grant assertion and the request
	// object, so its key must not share a field with them.
	ClientAssertionKey interface{}
	EncryptionKey      interface{}
	Cert               *x509.Certificate
}

func (r *Request) AuthorizeRequest(
	cconfig ClientConfig,
	sconfig ServerConfig,
	hc *http.Client,
) (codeVerifier string, err error) {
	r.Form = url.Values{
		"client_id":    {cconfig.ClientID},
		"redirect_uri": {cconfig.RedirectURL},
		"state":        {shortuuid.New()},
		"nonce":        {shortuuid.New()},
	}

	if len(cconfig.ResponseType) > 0 {
		r.Form.Set("response_type", strings.Join(cconfig.ResponseType, " "))
	}

	if cconfig.ResponseMode != "" {
		r.Form.Set("response_mode", cconfig.ResponseMode)
	}

	if len(cconfig.Scopes) > 0 {
		r.Form.Set("scope", strings.Join(cconfig.Scopes, " "))
	}

	if len(cconfig.ACRValues) > 0 {
		r.Form.Set("acr_values", strings.Join(cconfig.ACRValues, " "))
	}

	if len(cconfig.Audience) > 0 {
		r.Form.Set("audience", strings.Join(cconfig.Audience, " "))
	}

	for _, resource := range cconfig.Resource {
		r.Form.Add("resource", resource)
	}

	if len(cconfig.Purpose) > 0 {
		r.Form.Set("purpose", cconfig.Purpose)
	}

	if len(cconfig.Prompt) > 0 {
		r.Form.Set("prompt", strings.Join(cconfig.Prompt, " "))
	}

	if len(cconfig.MaxAge) > 0 {
		r.Form.Set("max_age", cconfig.MaxAge)
	}

	if len(cconfig.AuthenticationCode) > 0 {
		r.Form.Set("authentication_code", cconfig.AuthenticationCode)
	}

	if cconfig.IDTokenHint != "" {
		r.Form.Set("id_token_hint", cconfig.IDTokenHint)
	}

	if cconfig.LoginHint != "" {
		r.Form.Set("login_hint", cconfig.LoginHint)
	}

	if cconfig.IDPHint != "" {
		r.Form.Set("idp_hint", cconfig.IDPHint)
	}

	if cconfig.PKCE {
		codeVerifier = RandomString(CodeVerifierLength)

		hash := sha256.New()

		if _, err = hash.Write([]byte(codeVerifier)); err != nil {
			return "", err
		}

		codeChallenge := CodeChallengeEncoder.EncodeToString(hash.Sum([]byte{}))

		r.Form.Set("code_challenge", codeChallenge)
		r.Form.Set("code_challenge_method", "S256")
	}

	if cconfig.Claims != "" {
		r.Form.Set("claims", cconfig.Claims)
	}

	if cconfig.RAR != "" {
		r.Form.Set("authorization_details", cconfig.RAR)
	}

	if cconfig.RequestObject || cconfig.EncryptedRequestObject {
		claims := RequestObjectClaims(r.Form, sconfig, cconfig)

		if cconfig.SigningKey != "" {
			if r.RequestObject, r.SigningKey, err = SignJWT(claims, JWKSigner(cconfig.SigningKey, hc)); err != nil {
				return "", err
			}
		} else {
			if r.RequestObject, r.SigningKey, err = PlaintextJWT(claims); err != nil {
				return "", err
			}
		}

		r.Form = url.Values{
			"client_id": {cconfig.ClientID},
			"request":   {r.RequestObject},
			"scope":     {"openid"},
		}

		if cconfig.EncryptedRequestObject {
			var encryptedRequestObject string

			if encryptedRequestObject, r.EncryptionKey, err = EncryptJWT(r.RequestObject, JWEEncrypter(sconfig.JWKsURI, hc)); err != nil {
				return "", err
			}

			r.Form.Set("request", encryptedRequestObject)
		}

		if len(cconfig.Scopes) > 0 {
			r.Form.Set("scope", strings.Join(cconfig.Scopes, " "))
		}

		if len(cconfig.ACRValues) > 0 {
			r.Form.Set("acr_values", strings.Join(cconfig.ACRValues, " "))
		}

		if len(cconfig.Audience) > 0 {
			r.Form.Set("audience", strings.Join(cconfig.Audience, " "))
		}

		for _, resource := range cconfig.Resource {
			r.Form.Add("resource", resource)
		}

		if len(cconfig.Purpose) > 0 {
			r.Form.Set("purpose", cconfig.Purpose)
		}

		if len(cconfig.Prompt) > 0 {
			r.Form.Set("prompt", strings.Join(cconfig.Prompt, " "))
		}

		if len(cconfig.MaxAge) > 0 {
			r.Form.Set("max_age", cconfig.MaxAge)
		}

		if len(cconfig.AuthenticationCode) > 0 {
			r.Form.Set("authentication_code", cconfig.AuthenticationCode)
		}
	}

	if cconfig.DPoP {
		var jkt string

		if jkt, err = DPoPThumbprint(cconfig.SigningKey, hc); err != nil {
			return "", err
		}

		r.Form.Set("dpop_jkt", jkt)
	}

	return codeVerifier, nil
}

func (r *Request) AuthenticateClient(
	endpoint string,
	mtlsEndpoint string,
	cconfig ClientConfig,
	sconfig ServerConfig,
	hc *http.Client,
) (string, error) {
	var err error

	switch cconfig.AuthMethod {
	case NoneAuthMethod:
		r.Form.Set("client_id", cconfig.ClientID)
	case ClientSecretPostAuthMethod:
		r.Form.Set("client_id", cconfig.ClientID)
		r.Form.Set("client_secret", cconfig.ClientSecret)
	case ClientSecretJwtAuthMethod:
		var clientAssertion string

		if clientAssertion, r.ClientAssertionKey, err = SignJWT(
			ClientAssertionClaims(sconfig, cconfig),
			SecretSigner([]byte(cconfig.ClientSecret)),
		); err != nil {
			return endpoint, err
		}

		r.Form.Set("client_assertion_type", JwtBearerClientAssertion)
		r.Form.Set("client_assertion", clientAssertion)
	case PrivateKeyJwtAuthMethod:
		var clientAssertion string

		if clientAssertion, r.ClientAssertionKey, err = SignJWT(
			ClientAssertionClaims(sconfig, cconfig),
			JWKSigner(cconfig.SigningKey, hc),
		); err != nil {
			return endpoint, err
		}

		r.Form.Set("client_assertion_type", JwtBearerClientAssertion)
		r.Form.Set("client_assertion", clientAssertion)
	case TLSClientAuthMethod, SelfSignedTLSAuthMethod:
		r.Form.Set("client_id", cconfig.ClientID)
	}

	if tr, ok := hc.Transport.(*http.Transport); ok {
		if len(tr.TLSClientConfig.Certificates) > 0 {
			r.Cert, _ = x509.ParseCertificate(tr.TLSClientConfig.Certificates[0].Certificate[0])
			endpoint = mtlsEndpoint
		}
	}

	return endpoint, nil
}

func (r *Request) Get(key string) string {
	if v, ok := r.JARM[key].(string); ok {
		return v
	}

	if v := r.URL.Query().Get(key); v != "" {
		return v
	}

	return r.Form.Get(key)
}

func (r *Request) ParseJARM(signingKey interface{}, encryptionKey interface{}) error {
	var (
		response    = r.Get("response")
		token       *jwt.JSONWebToken
		nestedToken *jwt.NestedJSONWebToken
		err         error
		err2        error
	)

	r.JARM = map[string]interface{}{}

	if nestedToken, err = jwt.ParseSignedAndEncrypted(response, JOSEKeyAlgorithms, JOSEContentEncryption, JOSESignatureAlgorithms); err != nil {
		if token, err2 = jwt.ParseSigned(response, JOSESignatureAlgorithms); err2 != nil {
			return errors.Wrapf(multierror.Append(err, err2), "failed to parse JARM response")
		}
	} else if encryptionKey != nil {
		if token, err = nestedToken.Decrypt(encryptionKey); err != nil {
			return errors.Wrapf(err, "failed to decrypt encrypted JARM response")
		}
	} else {
		return errors.New("no encryption key path")
	}

	if signingKey == nil {
		return errors.New("no signing key path")
	}

	if err = token.Claims(signingKey, &r.JARM); err != nil {
		return err
	}

	return nil
}
