package adkconfig

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/kagent-dev/kagent/go/core/internal/translator"
)

func TestDedicatedRemoteAgents(t *testing.T) {
	const controlPlane = "http://kagent-v1-controller.kagent-v1.svc.cluster.local:8083"

	require.Nil(t, DedicatedRemoteAgents(controlPlane, "troubleshooting", nil))

	agents := DedicatedRemoteAgents(controlPlane, "troubleshooting", []translator.DedicatedBinding{{
		Name: "telemetry_agent", Description: "T", AgentRef: corev1.LocalObjectReference{Name: "telemetry-agent"},
	}})
	require.Len(t, agents, 1)
	require.Equal(t, "telemetry_agent", agents[0].Name)
	require.Equal(t, "T", agents[0].Description)
	require.Equal(t, controlPlane+"/agents/troubleshooting/telemetry-agent/.well-known/agent-card.json", agents[0].Url)
	require.Equal(t, 30*time.Minute, agents[0].Timeout.AsDuration())
	require.False(t, agents[0].IsolateSessions)
}

func TestDedicatedRemoteAgentsToleratesTrailingSlash(t *testing.T) {
	agents := DedicatedRemoteAgents("http://controller:8083/", "ns", []translator.DedicatedBinding{{
		Name: "peer", Description: "d", AgentRef: corev1.LocalObjectReference{Name: "peer-agent"},
	}})
	require.Equal(t, "http://controller:8083/agents/ns/peer-agent/.well-known/agent-card.json", agents[0].Url)
}
