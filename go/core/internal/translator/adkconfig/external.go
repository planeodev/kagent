package adkconfig

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	configv1 "github.com/kagent-dev/kagent/go/api/gen/kagent/config/v1"
	"github.com/kagent-dev/kagent/go/core/internal/egress"
)

// ExternalA2AAnnotation lists A2A agents outside kagent that an Agent (or its
// AgentTemplate) may call directly, bypassing the controller gateway. The value
// is a JSON list of {name, description, url, timeoutSeconds?}; url is the peer's
// agent card URL. SURF extension, not part of the upstream API.
const ExternalA2AAnnotation = "kagent.surf.net/remote-agents"

type externalRemoteAgent struct {
	Name           string `json:"name"`
	Description    string `json:"description"`
	URL            string `json:"url"`
	TimeoutSeconds *int64 `json:"timeoutSeconds,omitempty"`
}

// ExternalRemoteAgents reads ExternalA2AAnnotation and returns the ADK remote
// agents plus the egress origins they need. controlPlaneURL is the controller:
// kagent Agents must be declared with subAgent.agentRef so the gateway
// authorizes the call.
func ExternalRemoteAgents(controlPlaneURL string, annotations map[string]string) ([]*configv1.ADKRemoteAgentConfig, []string, error) {
	raw := strings.TrimSpace(annotations[ExternalA2AAnnotation])
	if raw == "" {
		return nil, nil, nil
	}
	var entries []externalRemoteAgent
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, nil, fmt.Errorf("annotation %s must be a JSON list of {name, description, url, timeoutSeconds}: %w", ExternalA2AAnnotation, err)
	}
	controller, err := url.Parse(controlPlaneURL)
	if err != nil {
		return nil, nil, fmt.Errorf("parse control plane URL: %w", err)
	}
	controllerOrigin := egress.Origin(controller)

	var agents []*configv1.ADKRemoteAgentConfig
	var origins []string
	names := map[string]struct{}{}
	for i, entry := range entries {
		fail := func(format string, args ...any) ([]*configv1.ADKRemoteAgentConfig, []string, error) {
			return nil, nil, fmt.Errorf("annotation %s entry %d: %s", ExternalA2AAnnotation, i, fmt.Sprintf(format, args...))
		}
		switch {
		case entry.Name == "":
			return fail("name is required")
		case entry.Description == "":
			return fail("description is required for %q", entry.Name)
		}
		if _, ok := names[entry.Name]; ok {
			return fail("duplicate name %q", entry.Name)
		}
		names[entry.Name] = struct{}{}
		target, err := url.Parse(entry.URL)
		if err != nil || (target.Scheme != "http" && target.Scheme != "https") || target.Hostname() == "" {
			return fail("url %q for %q must be an absolute http(s) URL", entry.URL, entry.Name)
		}
		if _, err := netip.ParseAddr(target.Hostname()); err == nil {
			return fail("url %q for %q uses an IP-literal host; Substrate egress requires a DNS name", entry.URL, entry.Name)
		}
		origin := egress.Origin(target)
		if origin == controllerOrigin {
			return fail("url %q for %q points at the controller: use subAgent.agentRef for kagent Agents", entry.URL, entry.Name)
		}
		timeout := remoteAgentTimeout
		if entry.TimeoutSeconds != nil {
			if *entry.TimeoutSeconds <= 0 || *entry.TimeoutSeconds > int64(24*time.Hour/time.Second) {
				return fail("timeoutSeconds for %q must be between 1 and 86400", entry.Name)
			}
			timeout = time.Duration(*entry.TimeoutSeconds) * time.Second
		}
		agents = append(agents, &configv1.ADKRemoteAgentConfig{
			Name: entry.Name, Description: entry.Description, Url: entry.URL, Timeout: durationpb.New(timeout),
		})
		origins = append(origins, origin)
	}
	slices.Sort(origins)
	return agents, slices.Compact(origins), nil
}
