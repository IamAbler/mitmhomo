package config

import (
	"strings"
	"testing"

	"github.com/metacubex/mihomo/component/mitm/httphook"
	"github.com/stretchr/testify/require"
)

const httpScriptYAML = `mitm:
  http-script:
    enable: true
    max-body-bytes: 32768
    rules:
      - name: add-header
        phase: request
        match:
          domains: [api.example.test]
          path-prefix: /v1/
          methods: [GET, POST]
        source: |
          ({headers: Object.assign({}, input.headers, {"X-Script": ["on"]})})
      - name: replace-response
        phase: response
        match:
          response-status: [200]
        source: |
          ({status: 201, body: input.body + "!"})
`

func TestHTTPScriptYAMLAndLazySnapshot(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte(httpScriptYAML))
	require.NoError(t, err)
	config := httphook.Config(raw.MITM.HTTPScript)
	snapshot, err := httphook.Compile(config)
	require.NoError(t, err)
	require.NotNil(t, snapshot)
	require.False(t, snapshot.RuntimeInitialized(), "configuration compilation must not create a JS Runtime")
	require.NoError(t, snapshot.Close())
}

func TestHTTPScriptYAMLRejectsUnknownFieldsAndInvalidRules(t *testing.T) {
	unknown := strings.Replace(httpScriptYAML, "        phase: request", "        stage: request", 1)
	_, err := UnmarshalRawConfig([]byte(unknown))
	require.ErrorContains(t, err, "mitm.http-script")
	require.ErrorContains(t, err, "unknown field")

	raw := RawMITM{
		Enable:  true,
		Domains: []string{"api.example.test"},
		HTTPScript: RawHTTPScript(httphook.Config{
			Enable: true,
			Rules:  []httphook.Rule{{Name: "bad", Phase: "request", Source: `null`, Match: httphook.Match{ResponseStatus: []int{200}}}},
		}),
	}
	_, err = parseMITM(raw)
	require.ErrorContains(t, err, "mitm.http-script")
}

func TestDisabledMITMIgnoresScriptHooks(t *testing.T) {
	parsed, err := parseMITM(RawMITM{HTTPScript: RawHTTPScript(httphook.Config{
		Enable: true,
		Rules:  []httphook.Rule{{Name: "invalid", Phase: "unknown"}},
	})})
	require.NoError(t, err)
	require.False(t, parsed.Enabled)
	require.Nil(t, parsed.ScriptHooks)
}
