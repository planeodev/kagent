package runtimeauth_test

// Planeo fork patch tests (delegation.go): an actor may reach ONLY peer Agents its Agent/AgentTemplate declares,
// in its own namespace; everything else keeps upstream's actor policy.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/kagent-dev/kagent/go/api/v1alpha3"
	authimpl "github.com/kagent-dev/kagent/go/core/internal/httpserver/auth"
	"github.com/kagent-dev/kagent/go/core/internal/jwttest"
	"github.com/kagent-dev/kagent/go/core/internal/runtimeauth"
	"github.com/kagent-dev/kagent/go/core/internal/substrate"
	"github.com/kagent-dev/kagent/go/core/pkg/auth"
)

type delegationFixture struct {
	provider *runtimeauth.Provider
	actor    auth.Session
	session  string
}

// newDelegationFixture authenticates a real actor of Agent team-a/agent (session owner "owner").
func newDelegationFixture(t *testing.T) delegationFixture {
	t.Helper()
	issuer := jwttest.New(t)
	verifier, err := substrate.NewActorJWTVerifier(t.Context(), issuer.URL, issuer.CAFile)
	require.NoError(t, err)
	store := newBinding()
	provider := runtimeauth.NewProvider(authimpl.NewProxyAuthenticator("sub"), verifier, store, issuer.URL)
	actor, err := provider.Authenticate(t.Context(), http.Header{"Authorization": {"Bearer " + issuer.Token(t, issuer.Claims("team-a", substrate.ActorName(store.session.Id), store.actorUID))}}, nil)
	require.NoError(t, err)
	require.NotNil(t, actor.Principal().Actor)
	return delegationFixture{provider: provider, actor: actor, session: store.session.Id}
}

func kube(t *testing.T, objects ...client.Object) client.Reader {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha3.AddToScheme(scheme))
	return fake.NewClientBuilder().WithScheme(scheme).WithObjects(objects...).Build()
}

func callerAgent(annotations map[string]string, template string) *v1alpha3.Agent {
	agent := &v1alpha3.Agent{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: "agent", Annotations: annotations}}
	if template != "" {
		agent.Spec.Template.Ref = &corev1.LocalObjectReference{Name: template}
	}
	return agent
}

func template(name string, annotations map[string]string) *v1alpha3.AgentTemplate {
	return &v1alpha3.AgentTemplate{ObjectMeta: metav1.ObjectMeta{Namespace: "team-a", Name: name, Annotations: annotations}}
}

func delegate(t *testing.T, f delegationFixture, reader client.Reader, target types.NamespacedName) auth.Principal {
	t.Helper()
	ctx, err := runtimeauth.NewPeerDelegator(reader).DelegatePeer(auth.AuthSessionTo(context.Background(), f.actor), target)
	require.NoError(t, err)
	session, ok := auth.AuthSessionFrom(ctx)
	require.True(t, ok)
	return session.Principal()
}

func TestDeclaredPeerIsDelegatedToTheSessionOwner(t *testing.T) {
	f := newDelegationFixture(t)
	for name, reader := range map[string]client.Reader{
		"on the AgentTemplate": kube(t, callerAgent(nil, "coordinator"), template("coordinator", map[string]string{runtimeauth.AgentRefsAnnotation: "other, peer"})),
		"on the Agent":         kube(t, callerAgent(map[string]string{runtimeauth.AgentRefsAnnotation: "peer"}, "")),
	} {
		t.Run(name, func(t *testing.T) {
			principal := delegate(t, f, reader, types.NamespacedName{Namespace: "team-a", Name: "peer"})
			require.Nil(t, principal.Actor, "a delegated call is not an actor any more")
			require.Equal(t, "owner", principal.User.ID)
			require.Equal(t, "team-a/agent", principal.Agent.ID)
			require.Equal(t, f.session, principal.Claims[runtimeauth.DelegatedFromSessionClaim])
		})
	}
}

func TestUndeclaredCrossNamespaceAndSelfStayActors(t *testing.T) {
	f := newDelegationFixture(t)
	declared := map[string]string{runtimeauth.AgentRefsAnnotation: "peer"}
	for name, test := range map[string]struct {
		reader client.Reader
		target types.NamespacedName
	}{
		"not declared":                {kube(t, callerAgent(nil, "coordinator"), template("coordinator", nil)), types.NamespacedName{Namespace: "team-a", Name: "peer"}},
		"declared elsewhere only":     {kube(t, callerAgent(nil, "coordinator"), template("coordinator", map[string]string{runtimeauth.AgentRefsAnnotation: "peer-2"})), types.NamespacedName{Namespace: "team-a", Name: "peer"}},
		"cross-namespace, never":      {kube(t, callerAgent(declared, "")), types.NamespacedName{Namespace: "team-b", Name: "peer"}},
		"own Agent: upstream path":    {kube(t, callerAgent(declared, "")), types.NamespacedName{Namespace: "team-a", Name: "agent"}},
		"caller Agent gone":           {kube(t), types.NamespacedName{Namespace: "team-a", Name: "peer"}},
		"template missing":            {kube(t, callerAgent(nil, "missing")), types.NamespacedName{Namespace: "team-a", Name: "peer"}},
		"prefix is not a declaration": {kube(t, callerAgent(map[string]string{runtimeauth.AgentRefsAnnotation: "peer-x"}, "")), types.NamespacedName{Namespace: "team-a", Name: "peer"}},
	} {
		t.Run(name, func(t *testing.T) {
			principal := delegate(t, f, test.reader, test.target)
			require.NotNil(t, principal.Actor, "stays an actor, so upstream's actor policy decides")
			require.Equal(t, f.session, principal.Actor.SessionID)
		})
	}
}

func TestUsersAreNeverDelegated(t *testing.T) {
	user := authimpl.NewProxyAuthenticator("sub")
	session, err := user.Authenticate(t.Context(), http.Header{"Authorization": {"Bearer e30.eyJzdWIiOiJhbGljZSJ9.sig"}}, nil)
	require.NoError(t, err)
	reader := kube(t, callerAgent(map[string]string{runtimeauth.AgentRefsAnnotation: "peer"}, ""))
	ctx, err := runtimeauth.NewPeerDelegator(reader).DelegatePeer(auth.AuthSessionTo(context.Background(), session), types.NamespacedName{Namespace: "team-a", Name: "peer"})
	require.NoError(t, err)
	got, _ := auth.AuthSessionFrom(ctx)
	require.Equal(t, session, got)
}

func TestDelegatedUpstreamSendsOwnerWithoutBearer(t *testing.T) {
	f := newDelegationFixture(t)
	reader := kube(t, callerAgent(map[string]string{runtimeauth.AgentRefsAnnotation: "peer"}, ""))
	ctx, err := runtimeauth.NewPeerDelegator(reader).DelegatePeer(auth.AuthSessionTo(context.Background(), f.actor), types.NamespacedName{Namespace: "team-a", Name: "peer"})
	require.NoError(t, err)
	delegated, _ := auth.AuthSessionFrom(ctx)
	request := httptest.NewRequest(http.MethodPost, "http://runtime", nil)
	request.Header.Set("Authorization", "Bearer actor-or-user-token")
	require.NoError(t, f.provider.UpstreamAuth(request, delegated, auth.Principal{Agent: auth.Agent{ID: "peer-session"}}))
	require.Empty(t, request.Header.Get("Authorization"), "no bearer ever reaches the peer runtime")
	require.Equal(t, "owner", request.Header.Get("X-User-Id"))
}

type denyActors struct{ auth.NoopAuthorizer }

func TestAuthorizerUsesUserPolicyForDelegatedAndActorPolicyOtherwise(t *testing.T) {
	f := newDelegationFixture(t)
	store := newBinding()
	authorizer := runtimeauth.NewAuthorizer(denyActors{}, store)
	peer := auth.Resource{Type: "Agent", Namespace: "team-a", Name: "peer"}
	ctx := auth.AuthSessionTo(context.Background(), f.actor)
	require.Error(t, authorizer.Check(ctx, f.actor.Principal(), auth.VerbGet, peer), "an actor alone still cannot read another Agent")
	reader := kube(t, callerAgent(map[string]string{runtimeauth.AgentRefsAnnotation: "peer"}, ""))
	delegatedCtx, err := runtimeauth.NewPeerDelegator(reader).DelegatePeer(ctx, types.NamespacedName{Namespace: "team-a", Name: "peer"})
	require.NoError(t, err)
	delegated, _ := auth.AuthSessionFrom(delegatedCtx)
	require.NoError(t, authorizer.Check(delegatedCtx, delegated.Principal(), auth.VerbGet, peer), "the declared peer goes through the user authorizer")
}
