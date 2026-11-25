package adkconfig

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	configv1 "github.com/kagent-dev/kagent/go/api/gen/kagent/config/v1"
	"github.com/kagent-dev/kagent/go/core/internal/translator"
)

// remoteAgentTimeout bounds one call to a peer Agent. A peer runs a full agent
// loop, so the bound is generous; it matches the kagent 0.10 default.
const remoteAgentTimeout = 30 * time.Minute

// DedicatedRemoteAgents turns subAgent.agentRef bindings into ADK remote A2A
// agents that call the peer through the controller's A2A gateway.
//
// The card URL carries the gateway path, which a2a-go fetches verbatim
// (kagent#3275). The compiled output depends only on the parent's own spec: a
// missing peer surfaces at call time as a gateway 404.
func DedicatedRemoteAgents(controlPlaneURL, namespace string, bindings []translator.DedicatedBinding) []*configv1.ADKRemoteAgentConfig {
	if len(bindings) == 0 {
		return nil
	}
	base := strings.TrimRight(controlPlaneURL, "/")
	agents := make([]*configv1.ADKRemoteAgentConfig, 0, len(bindings))
	for _, binding := range bindings {
		agents = append(agents, &configv1.ADKRemoteAgentConfig{
			Name:        binding.Name,
			Description: binding.Description,
			Url:         base + "/agents/" + namespace + "/" + binding.AgentRef.Name + "/.well-known/agent-card.json",
			Timeout:     durationpb.New(remoteAgentTimeout),
		})
	}
	return agents
}
