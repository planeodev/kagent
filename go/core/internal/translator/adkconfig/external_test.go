package adkconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExternalRemoteAgents(t *testing.T) {
	const wfo = `{"name":"wfo_search","description":"W","url":"http://wfo-search.troubleshooting.svc.cluster.local:8080/.well-known/agent-card.json","timeoutSeconds":1800}`
	for _, tc := range []struct {
		name        string
		annotations map[string]string
		wantAgents  int
		wantError   string
	}{
		{name: "none"},
		{name: "empty annotation", annotations: map[string]string{ExternalA2AAnnotation: ""}},
		{
			name: "wfo-search", annotations: map[string]string{ExternalA2AAnnotation: "[" + wfo + "]"},
			wantAgents: 1,
		},
		{
			name: "missing timeoutSeconds", wantAgents: 1,
			annotations: map[string]string{ExternalA2AAnnotation: `[{"name":"wfo","description":"W","url":"http://wfo.example.com/card.json"}]`},
		},
		{
			name: "missing description", wantError: "description",
			annotations: map[string]string{ExternalA2AAnnotation: `[{"name":"wfo","url":"http://wfo.example.com/card.json"}]`},
		},
		{
			name: "missing name", wantError: "name",
			annotations: map[string]string{ExternalA2AAnnotation: `[{"description":"W","url":"http://wfo.example.com/card.json"}]`},
		},
		{
			name: "duplicate name", wantError: "duplicate",
			annotations: map[string]string{ExternalA2AAnnotation: `[` + wfo + `,` + wfo + `]`},
		},
		{
			name: "invalid JSON", wantError: ExternalA2AAnnotation,
			annotations: map[string]string{ExternalA2AAnnotation: `{not json`},
		},
		{
			name: "IP-literal URL", wantError: "IP",
			annotations: map[string]string{ExternalA2AAnnotation: `[{"name":"wfo","description":"W","url":"http://10.1.2.3:8080/card.json"}]`},
		},
		{
			name: "non-HTTP URL", wantError: "url",
			annotations: map[string]string{ExternalA2AAnnotation: `[{"name":"wfo","description":"W","url":"ftp://wfo.example.com/card.json"}]`},
		},
		{
			name: "negative timeout", wantError: "timeoutSeconds",
			annotations: map[string]string{ExternalA2AAnnotation: `[{"name":"wfo","description":"W","url":"http://wfo.example.com/card.json","timeoutSeconds":-1}]`},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agents, err := ExternalRemoteAgents("http://kagent-controller.kagent:8083", tc.annotations)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				return
			}
			require.NoError(t, err)
			require.Len(t, agents, tc.wantAgents)
			if tc.wantAgents == 0 {
				require.Nil(t, agents)
				return
			}
			require.Equal(t, 30*time.Minute, agents[0].Timeout.AsDuration())
			require.False(t, agents[0].IsolateSessions)
		})
	}
}

func TestExternalRemoteAgentsRejectsTheControllerOrigin(t *testing.T) {
	_, err := ExternalRemoteAgents("http://kagent-controller.kagent:8083", map[string]string{
		ExternalA2AAnnotation: `[{"name":"peer","description":"P","url":"http://kagent-controller.kagent:8083/agents/ns/peer/.well-known/agent-card.json"}]`,
	})
	require.ErrorContains(t, err, "use subAgent.agentRef for kagent Agents")
}
