package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/itchyny/gojq"
	"github.com/stretchr/testify/require"
)

const (
	IssuerURL = "https://oauth2c.us.authz.cloudentity.io/oauth2c/demo"

	ClientCredentialsScopes = "introspect_tokens,revoke_tokens"

	TLSCertURL    = "../data/cert.pem"
	TLSKeyURL     = "../data/key.pem"
	SigningKeyURL = "../data/rsa/key.json"
)

type CommandTestCase struct {
	title string
	args  []string
	deps  map[string]CommandDependency
	err   error
}

type CommandDependency struct {
	args []string
	jq   string
}

func (tc *CommandTestCase) Test() func(*testing.T) {
	return func(t *testing.T) {
		deps := tc.GetDeps(t)

		for i, arg := range tc.args {
			if strings.HasPrefix(arg, "$") {
				tc.args[i] = deps[arg[1:]]
			}
		}

		cmd := NewOAuth2Cmd("master", "none", "unknown")
		cmd.SetArgs(tc.args)
		err := cmd.Execute()

		if tc.err == nil {
			require.NoError(t, err)
		} else {
			require.Error(t, err)
			require.Equal(t, err.Error(), tc.err.Error())
		}
	}
}

func (tc *CommandTestCase) GetDeps(t *testing.T) map[string]string {
	deps := make(map[string]string)

	for name, dep := range tc.deps {
		output := bytes.Buffer{}
		result := map[string]interface{}{}

		cmd := NewOAuth2Cmd("master", "none", "unknown")
		cmd.SetArgs(dep.args)
		cmd.SetOut(&output)
		err := cmd.Execute()

		require.NoError(t, err)

		err = json.Unmarshal(output.Bytes(), &result)
		require.NoError(t, err)

		query, err := gojq.Parse(dep.jq)
		require.NoError(t, err)
		iter := query.Run(result)

		v, ok := iter.Next()
		require.True(t, ok)

		deps[name] = v.(string)
	}

	return deps
}
