package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
)

type BackchannelAuthenticationResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int64  `json:"expires_in"`
	Interval  *int64 `json:"interval"`
}

// ponytail: poll mode only; ping/push need a client notification endpoint
func RequestBackchannelAuthentication(ctx context.Context, cconfig ClientConfig, sconfig ServerConfig, hc *http.Client) (request Request, response BackchannelAuthenticationResponse, err error) {
	var (
		req      *http.Request
		resp     *http.Response
		endpoint string
	)

	if sconfig.BackchannelAuthenticationEndpoint == "" && sconfig.MTLsEndpointAliases.BackchannelAuthenticationEndpoint == "" {
		return request, response, errors.New("the server's backchannel authentication endpoint is not configured")
	}

	request.Form = url.Values{
		"scope": {strings.Join(cconfig.Scopes, " ")},
	}

	for k, v := range map[string]string{
		"login_hint":      cconfig.LoginHint,
		"id_token_hint":   cconfig.IDTokenHint,
		"binding_message": cconfig.BindingMessage,
		"acr_values":      strings.Join(cconfig.ACRValues, " "),
		"audience":        strings.Join(cconfig.Audience, " "),
	} {
		if v != "" {
			request.Form.Set(k, v)
		}
	}

	mtlsEndpoint := sconfig.MTLsEndpointAliases.BackchannelAuthenticationEndpoint
	if mtlsEndpoint == "" {
		mtlsEndpoint = sconfig.BackchannelAuthenticationEndpoint
	}

	if endpoint, err = request.AuthenticateClient(sconfig.BackchannelAuthenticationEndpoint, mtlsEndpoint, cconfig, sconfig, hc); err != nil {
		return request, response, err
	}

	if req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(request.Form.Encode())); err != nil {
		return request, response, err
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if cconfig.AuthMethod == ClientSecretBasicAuthMethod {
		req.SetBasicAuth(cconfig.ClientID, cconfig.ClientSecret)
	}

	request.Method = req.Method
	request.Headers = req.Header
	request.URL = req.URL

	if resp, err = hc.Do(req); err != nil {
		return request, response, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return request, response, ParseError(resp)
	}

	if err = json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return request, response, fmt.Errorf("failed to parse backchannel authentication response: %w", err)
	}

	return request, response, nil
}
