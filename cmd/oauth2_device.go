package cmd

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

func (c *OAuth2Cmd) DeviceGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		authorizationRequest  oauth2.Request
		authorizationResponse oauth2.DeviceAuthorizationResponse
		tokenRequest          oauth2.Request
		tokenResponse         oauth2.TokenResponse
		err                   error
	)

	LogHeader("Device Flow")

	// device authorization endpoint
	LogSection("Request device authorization")

	if authorizationRequest, authorizationResponse, err = oauth2.RequestDeviceAuthorization(context.Background(), clientConfig, serverConfig, hc); err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogRequestAndResponse(authorizationRequest, authorizationResponse)

	verificationUri := authorizationResponse.VerificationURI
	if authorizationResponse.VerificationURIComplete != nil {
		verificationUri = *authorizationResponse.VerificationURIComplete
	}

	LogAuthURL(verificationUri, clientConfig.NoBrowser)

	Logln()

	// polling
	tokenStatus := LogAction("Waiting for token. Go to the browser to authenticate...")

	tokenRequest, tokenResponse, err = pollToken(clientConfig, serverConfig, hc, authorizationResponse.Interval, oauth2.WithDeviceCode(authorizationResponse.DeviceCode))

	LogSection("Exchange device code for token")

	if err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogAuthMethod(clientConfig)
	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)

	tokenStatus("Obtained token")

	c.PrintResult(tokenResponse)

	return nil
}

func pollToken(
	clientConfig oauth2.ClientConfig,
	serverConfig oauth2.ServerConfig,
	hc *http.Client,
	intervalSec *int64,
	opt oauth2.RequestTokenOption,
) (tokenRequest oauth2.Request, tokenResponse oauth2.TokenResponse, err error) {
	var oauth2Error *oauth2.Error

	interval := 5 * time.Second
	if intervalSec != nil {
		interval = time.Duration(*intervalSec) * time.Second
	}

	for {
		time.Sleep(interval)

		if tokenRequest, tokenResponse, err = oauth2.RequestToken(context.Background(), clientConfig, serverConfig, hc, opt); err == nil {
			return tokenRequest, tokenResponse, nil
		}

		if !errors.As(err, &oauth2Error) {
			return tokenRequest, tokenResponse, err
		}

		switch oauth2Error.ErrorCode {
		case oauth2.ErrSlowDown:
			interval += 5 * time.Second
		case oauth2.ErrAuthorizationPending:
		default:
			return tokenRequest, tokenResponse, err
		}
	}
}
