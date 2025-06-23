package cmd

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/cli/browser"
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

	Logfln("\nGo to the following URL:\n\n%s", verificationUri)

	if !clientConfig.NoBrowser {
		Logfln("\nOpening browser...")
		if err = browser.OpenURL(verificationUri); err != nil {
			LogError(err)
		}
	}

	Logln()

	// polling
	tokenStatus := LogAction("Waiting for token. Go to the browser to authenticate...")

	interval := 5 * time.Second
	if authorizationResponse.Interval != nil {
		interval = time.Duration(*authorizationResponse.Interval) * time.Second
	}
	ticker := time.NewTicker(interval)
	done := make(chan error)

	go func() {
		var oauth2Error *oauth2.Error

		defer close(done)

		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if tokenRequest, tokenResponse, err = oauth2.RequestToken(
					context.Background(),
					clientConfig,
					serverConfig,
					hc,
					oauth2.WithDeviceCode(authorizationResponse.DeviceCode),
				); err != nil {
					if errors.As(err, &oauth2Error) {
						switch oauth2Error.ErrorCode {
						case oauth2.ErrAuthorizationPending, oauth2.ErrSlowDown:
							continue
						}
					}

					done <- err

					return
				} else {
					return
				}
			}
		}
	}()

	err = <-done

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
