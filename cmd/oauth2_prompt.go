package cmd

import "github.com/cloudentity/oauth2c/internal/oauth2"

func PromptForClientConfig(client oauth2.ClientConfig, server oauth2.ServerConfig) oauth2.ClientConfig {
	// grant type
	if client.GrantType == "" {
		client.GrantType = PromptStringSlice("Grant type", server.SupportedGrantTypes)
	}

	// auth method
	switch client.GrantType {
	case oauth2.AuthorizationCodeGrantType, oauth2.ClientCredentialsGrantType, oauth2.RefreshTokenGrantType, oauth2.PasswordGrantType, oauth2.JWTBearerGrantType, oauth2.CIBAGrantType:
		if client.AuthMethod == "" {
			client.AuthMethod = PromptStringSlice("Token endpoint auth method", server.SupportedTokenEndpointAuthMethods)
		}
	}

	// response types
	switch client.GrantType {
	case oauth2.AuthorizationCodeGrantType, oauth2.ImplicitGrantType:
		if len(client.ResponseType) == 0 || client.ResponseType[0] == "" {
			client.ResponseType = PromptMultiStringSlice("Response types", server.SupportedResponseTypes)
		}
	}

	// response mode
	switch client.GrantType {
	case oauth2.AuthorizationCodeGrantType, oauth2.ImplicitGrantType:
		if client.ResponseMode == "" {
			client.ResponseMode = PromptStringSlice("Response mode", server.SupportedResponseModes)
		}
	}

	if client.ClientID == "" {
		client.ClientID = PromptString("Client ID")
	}

	// client secret
	switch client.AuthMethod {
	case oauth2.ClientSecretBasicAuthMethod, oauth2.ClientSecretPostAuthMethod, oauth2.ClientSecretJwtAuthMethod:
		if client.ClientSecret == "" {
			client.ClientSecret = PromptString("Client secret")
		}
	}

	switch client.GrantType {
	case oauth2.PasswordGrantType:
		if client.Username == "" {
			client.Username = PromptString("Username")
		}

		if client.Password == "" {
			client.Password = PromptString("Password")
		}
	case oauth2.RefreshTokenGrantType:
		if client.RefreshToken == "" {
			client.RefreshToken = PromptString("Refresh token")
		}
	case oauth2.CIBAGrantType:
		if client.LoginHint == "" && client.IDTokenHint == "" {
			client.LoginHint = PromptString("Login hint")
		}
	}

	return client
}
