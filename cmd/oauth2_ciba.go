package cmd

import (
	"context"
	"net/http"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

func (c *OAuth2Cmd) CIBAGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	var (
		authenticationRequest  oauth2.Request
		authenticationResponse oauth2.BackchannelAuthenticationResponse
		tokenRequest           oauth2.Request
		tokenResponse          oauth2.TokenResponse
		err                    error
	)

	LogHeader("CIBA Flow")

	LogSection("Request backchannel authentication")

	if authenticationRequest, authenticationResponse, err = oauth2.RequestBackchannelAuthentication(context.Background(), clientConfig, serverConfig, hc); err != nil {
		LogRequestAndResponseln(authenticationRequest, err)
		return err
	}

	LogAuthMethod(clientConfig)
	LogRequestAndResponseln(authenticationRequest, authenticationResponse)

	tokenStatus := LogAction("Waiting for token. Approve the request on the authentication device...")

	tokenRequest, tokenResponse, err = pollToken(clientConfig, serverConfig, hc, authenticationResponse.Interval, oauth2.WithAuthReqID(authenticationResponse.AuthReqID))

	LogSection("Exchange auth_req_id for token")

	if err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)

	tokenStatus("Obtained token")

	c.PrintResult(tokenResponse)

	return nil
}
