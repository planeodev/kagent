package a2agateway

// Planeo fork patch tests: the HTTP handler hands /agents/<ns>/<name> to the PeerDelegator (runtimeauth/delegation.go)
// before routing, never for share-token requests, and keeps upstream behaviour without a delegator.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	a2atype "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/kagent-dev/kagent/go/core/pkg/auth"
)

type cardOnlyGateway struct {
	a2asrv.RequestHandler
	seen auth.Principal
}

func (g *cardOnlyGateway) GetExtendedAgentCard(ctx context.Context, _ *a2atype.GetExtendedAgentCardRequest) (*a2atype.AgentCard, error) {
	session, _ := auth.AuthSessionFrom(ctx)
	g.seen = session.Principal()
	return &a2atype.AgentCard{Name: "peer"}, nil
}

// insecureForTest authenticates every request with an empty principal (no Actor) and forwards nothing.
type insecureForTest struct{}

func (insecureForTest) Authenticate(context.Context, http.Header, url.Values) (auth.Session, error) {
	return auth.ControlPlaneSession{}, nil
}

func (insecureForTest) UpstreamAuth(*http.Request, auth.Session, auth.Principal) error { return nil }

type recordingDelegator struct {
	targets []types.NamespacedName
}

type delegatedPrincipal struct{}

func (delegatedPrincipal) Principal() auth.Principal {
	return auth.Principal{User: auth.User{ID: "owner"}}
}

func (d *recordingDelegator) DelegatePeer(ctx context.Context, target types.NamespacedName) (context.Context, error) {
	d.targets = append(d.targets, target)
	return auth.AuthSessionTo(ctx, delegatedPrincipal{}), nil
}

func TestAgentFromPath(t *testing.T) {
	for path, want := range map[string]types.NamespacedName{
		"/agents/team-a/peer":                             {Namespace: "team-a", Name: "peer"},
		"/agents/team-a/peer/":                            {Namespace: "team-a", Name: "peer"},
		"/agents/team-a/peer/.well-known/agent-card.json": {Namespace: "team-a", Name: "peer"},
	} {
		got, ok := agentFromPath(path)
		require.True(t, ok, path)
		require.Equal(t, want, got, path)
	}
	for _, path := range []string{"/agents/", "/agents/team-a", "/agents//peer", "/mcp"} {
		_, ok := agentFromPath(path)
		require.False(t, ok, path)
	}
}

func TestHTTPHandlerDelegatesDeclaredPeersBeforeRouting(t *testing.T) {
	gateway := &cardOnlyGateway{}
	delegator := &recordingDelegator{}
	handler := NewHTTPHandler(gateway, insecureForTest{}, nil, delegator)
	request := httptest.NewRequest(http.MethodGet, "/agents/team-a/peer/.well-known/agent-card.json", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, []types.NamespacedName{{Namespace: "team-a", Name: "peer"}}, delegator.targets)
	require.Equal(t, "owner", gateway.seen.User.ID, "the gateway sees the delegated principal")
}

func TestHTTPHandlerWithoutDelegatorKeepsUpstreamBehaviour(t *testing.T) {
	gateway := &cardOnlyGateway{}
	handler := NewHTTPHandler(gateway, insecureForTest{}, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/agents/team-a/peer/.well-known/agent-card.json", nil))
	require.Equal(t, http.StatusOK, response.Code)
	require.Equal(t, "", gateway.seen.User.ID)
}
