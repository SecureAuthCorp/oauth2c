package oauth2

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/pkg/errors"
)

func UnsafeParseJWT(token string) (*jwt.JSONWebToken, map[string]interface{}, error) {
	var (
		t      *jwt.JSONWebToken
		claims = map[string]interface{}{}
		err    error
	)

	if t, err = jwt.ParseSigned(token); err != nil {
		return nil, nil, err
	}

	if err = t.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, nil, err
	}

	return t, claims, nil
}

type SignerProvider func() (jose.Signer, interface{}, error)

func JWKSigner(keyPath string, hc *http.Client) SignerProvider {
	return func() (signer jose.Signer, _ interface{}, err error) {
		var key jose.JSONWebKey

		if keyPath == "" {
			return nil, nil, errors.New("no signing key path")
		}

		if key, err = ReadKey(SigningKey, keyPath, hc); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to read signing key from %s", keyPath)
		}

		if key.IsPublic() {
			return nil, nil, errors.New("signing key must be private")
		}

		if signer, err = jose.NewSigner(jose.SigningKey{
			Algorithm: jose.SignatureAlgorithm(key.Algorithm),
			Key:       key.Key,
		}, &jose.SignerOptions{
			ExtraHeaders: map[jose.HeaderKey]interface{}{"kid": key.KeyID},
		}); err != nil {
			return nil, nil, errors.Wrapf(err, "failed to create a signer")
		}

		return signer, key.Key, nil
	}
}

func SecretSigner(secret []byte) SignerProvider {
	return func() (jose.Signer, interface{}, error) {
		signer, err := jose.NewSigner(jose.SigningKey{
			Algorithm: jose.HS256,
			Key:       secret,
		}, nil)

		return signer, secret, err
	}
}

type ClaimsProvider func() (map[string]interface{}, error)

func AssertionClaims(serverConfig ServerConfig, clientConfig ClientConfig) ClaimsProvider {
	return func() (map[string]interface{}, error) {
		var err error

		claims := map[string]interface{}{
			"iss": serverConfig.TokenEndpoint,
			"aud": serverConfig.TokenEndpoint,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 10).Unix(),
			"jti": RandomString(20),
		}

		if clientConfig.Assertion == "" {
			clientConfig.Assertion = "{}"
		}

		if err = json.Unmarshal([]byte(clientConfig.Assertion), &claims); err != nil {
			return nil, err
		}

		return claims, nil
	}
}

func RequestObjectClaims(params url.Values, serverConfig ServerConfig, clientConfig ClientConfig) ClaimsProvider {
	return func() (map[string]interface{}, error) {
		claims := map[string]interface{}{
			"iss": clientConfig.ClientID,
			"aud": clientConfig.IssuerURL,
			"exp": time.Now().Add(time.Minute * 10).Unix(),
			"nbf": time.Now().Unix(),
		}

		for key, values := range params {
			if len(values) == 0 {
				continue
			}

			val := values[0]

			if len(val) > 0 && (val[0] == '{' || val[0] == '[') {
				claims[key] = json.RawMessage(val)
			} else {
				claims[key] = val
			}
		}

		return claims, nil
	}
}

func ClientAssertionClaims(serverConfig ServerConfig, clientConfig ClientConfig) ClaimsProvider {
	return func() (map[string]interface{}, error) {
		return map[string]interface{}{
			"iss": clientConfig.ClientID,
			"sub": clientConfig.ClientID,
			"aud": clientConfig.IssuerURL,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 10).Unix(),
			"jti": RandomString(20),
		}, nil
	}
}

func SignJWT(claimsProvider ClaimsProvider, signerProvider SignerProvider) (jwt string, key interface{}, err error) {
	var (
		signer jose.Signer
		claims map[string]interface{}
		jws    *jose.JSONWebSignature
		bs     []byte
	)

	if signer, key, err = signerProvider(); err != nil {
		return "", nil, errors.Wrapf(err, "failed to create signer")
	}

	if claims, err = claimsProvider(); err != nil {
		return "", nil, errors.Wrapf(err, "failed to build claims")
	}

	if bs, err = json.Marshal(claims); err != nil {
		return "", nil, errors.Wrapf(err, "failed to serialize claims")
	}

	if jws, err = signer.Sign(bs); err != nil {
		return "", nil, errors.Wrapf(err, "failed to sign jwt")
	}

	if jwt, err = jws.CompactSerialize(); err != nil {
		return "", nil, err
	}

	return jwt, key, nil
}

func PlaintextJWT(claimsProvider ClaimsProvider) (string, string, error) {
	var (
		claims     map[string]interface{}
		claimsJSON []byte
		err        error
	)

	if claims, err = claimsProvider(); err != nil {
		return "", "", errors.Wrapf(err, "failed to build claims")
	}

	if claimsJSON, err = json.Marshal(claims); err != nil {
		return "", "", errors.Wrapf(err, "failed to serialize claims")
	}

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)

	return header + "." + payload + ".", "none", nil
}
