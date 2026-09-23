package cmd

import (
	"context"
	"net/http"

	"github.com/cloudentity/oauth2c/internal/oauth2"
)

func (c *OAuth2Cmd) ClientCredentialsGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return c.tokenEndpointFlow("Client Credentials Flow", clientConfig, serverConfig, hc)
}

func (c *OAuth2Cmd) PasswordGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return c.tokenEndpointFlow("Resource Owner Password Credentials Flow", clientConfig, serverConfig, hc)
}

func (c *OAuth2Cmd) RefreshTokenGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return c.tokenEndpointFlow("Refresh Token Flow", clientConfig, serverConfig, hc)
}

func (c *OAuth2Cmd) JWTBearerGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return c.tokenEndpointFlow("JWT Bearer Grant Flow", clientConfig, serverConfig, hc)
}

func (c *OAuth2Cmd) TokenExchangeGrantFlow(clientConfig oauth2.ClientConfig, serverConfig oauth2.ServerConfig, hc *http.Client) error {
	return c.tokenEndpointFlow("Token Exchange Grant Flow", clientConfig, serverConfig, hc)
}

func (c *OAuth2Cmd) tokenEndpointFlow(
	name string,
	clientConfig oauth2.ClientConfig,
	serverConfig oauth2.ServerConfig,
	hc *http.Client,
	requestTokenOpts ...oauth2.RequestTokenOption,
) error {

	var (
		tokenRequest  oauth2.Request
		tokenResponse oauth2.TokenResponse
		err           error
	)

	LogHeader(name)

	// request token
	LogSection("Request authorization")

	authorizationStatus := LogAction("Requesting authorization")

	if tokenRequest, tokenResponse, err = oauth2.RequestToken(
		context.Background(),
		clientConfig,
		serverConfig,
		hc,
		requestTokenOpts...,
	); err != nil {
		LogRequestAndResponseln(tokenRequest, err)
		return err
	}

	LogAssertion(tokenRequest, "Assertion", "assertion", tokenRequest.SigningKey)
	LogAssertion(tokenRequest, "Client assertion", "client_assertion", tokenRequest.ClientAssertionKey)
	LogSubjectTokenAndActorToken(tokenRequest)
	LogAuthMethod(clientConfig)
	LogRequestAndResponse(tokenRequest, tokenResponse)
	LogTokenPayloadln(tokenResponse)

	authorizationStatus("Authorization completed")

	c.PrintResult(tokenResponse)

	return nil
}
