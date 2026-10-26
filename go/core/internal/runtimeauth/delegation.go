package runtimeauth

// NOTE: Planeo fork patch — upstream defers agentRef
// (https://github.com/kagent-dev/kagent/pull/3007: "Deferred until Dedicated subagents can create and invoke
// their own Session"); remove when upstream ships Dedicated subagents. Carried on planeodev/kagent
// planeo/v1.0.0-alpha17; contract in planeodev/planeo-infra
// knowledge/decisions/agent-to-agent-on-kagent-1-0-templateref-vs-declared-agentref.md.
//
// Stock alpha17 lets an actor reach only its OWN Agent through the controller (Authorizer.Check), and Substrate
// stamps the actor's JWT on every request to the controller origin, so one Agent can never call another. This
// file adds exactly one exception: an actor calling the A2A gateway for a DIFFERENT Agent that is
//   1. in the actor's own namespace, and
//   2. declared by the caller — annotation AgentRefsAnnotation on the caller's Agent or on its referenced
//      AgentTemplate (the CRD-free form of the deferred `subAgent.agentRef`),
// is served on behalf of the actor session's owner (the Session creator), with the calling Agent and Session
// recorded on the principal. Everything else is left exactly as upstream: undeclared or cross-namespace targets
// stay actor requests and are denied by Authorizer.Check.

import (
	"context"
	"fmt"
	"strings"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/kagent-dev/kagent/go/api/v1alpha3"
	"github.com/kagent-dev/kagent/go/core/pkg/auth"
)

// AgentRefsAnnotation lists, comma-separated, the names of same-namespace Agents the annotated Agent (or every
// Agent of the annotated AgentTemplate) may invoke over A2A.
const AgentRefsAnnotation = "kagent.planeo.dev/agent-refs"

// DelegatedFromSessionClaim records, on a delegated principal, the actor Session that made the call.
const DelegatedFromSessionClaim = "kagent.planeo.dev/delegated-from-session"

// PeerDelegator turns an actor's call to a declared peer Agent into a call on behalf of its session owner.
type PeerDelegator struct {
	kube client.Reader
}

// NewPeerDelegator returns a delegator that reads declarations through kube.
func NewPeerDelegator(kube client.Reader) *PeerDelegator {
	return &PeerDelegator{kube: kube}
}

// DelegatePeer returns ctx with a delegated session when the authenticated actor may invoke target, and ctx
// unchanged otherwise (the caller is not an actor, the target is its own Agent, or nothing declares it — the
// regular authorization then decides, and denies an actor).
func (d *PeerDelegator) DelegatePeer(ctx context.Context, target types.NamespacedName) (context.Context, error) {
	if d == nil {
		return ctx, nil
	}
	authSession, ok := auth.AuthSessionFrom(ctx)
	if !ok {
		return ctx, nil
	}
	actor, ok := authSession.(runtimeSession)
	if !ok || actor.owner == "" {
		return ctx, nil
	}
	callerNamespace, callerName, ok := strings.Cut(actor.agent, "/")
	if !ok || callerNamespace == "" || callerName == "" {
		return ctx, nil
	}
	if target.Namespace != callerNamespace || target.Name == "" || target.Name == callerName {
		return ctx, nil
	}
	declared, err := d.declares(ctx, types.NamespacedName{Namespace: callerNamespace, Name: callerName}, target.Name)
	if err != nil {
		return ctx, err
	}
	if !declared {
		return ctx, nil
	}
	return auth.AuthSessionTo(ctx, delegatedSession{owner: actor.owner, agent: actor.agent, sessionID: actor.sessionID}), nil
}

// declares reports whether the caller Agent, or the AgentTemplate it references, lists peer in AgentRefsAnnotation.
func (d *PeerDelegator) declares(ctx context.Context, caller types.NamespacedName, peer string) (bool, error) {
	var agent v1alpha3.Agent
	if err := d.kube.Get(ctx, caller, &agent); err != nil {
		return false, client.IgnoreNotFound(err)
	}
	if listed(agent.GetAnnotations()[AgentRefsAnnotation], peer) {
		return true, nil
	}
	ref := agent.Spec.Template.Ref
	if ref == nil || ref.Name == "" {
		return false, nil
	}
	var template v1alpha3.AgentTemplate
	if err := d.kube.Get(ctx, types.NamespacedName{Namespace: caller.Namespace, Name: ref.Name}, &template); err != nil {
		if client.IgnoreNotFound(err) == nil {
			return false, nil
		}
		return false, fmt.Errorf("read AgentTemplate %s/%s: %w", caller.Namespace, ref.Name, err)
	}
	return listed(template.GetAnnotations()[AgentRefsAnnotation], peer), nil
}

func listed(value, name string) bool {
	for _, entry := range strings.Split(value, ",") {
		if strings.TrimSpace(entry) == name {
			return true
		}
	}
	return false
}

// delegatedSession is a user principal (the actor session's owner) acting for a declared peer call. It is not an
// actor: the user authorizer decides, and upstream dials send the owner as X-User-Id without any bearer.
type delegatedSession struct{ owner, agent, sessionID string }

func (s delegatedSession) Principal() auth.Principal {
	return auth.Principal{
		User:   auth.User{ID: s.owner},
		Agent:  auth.Agent{ID: s.agent},
		Claims: map[string]any{DelegatedFromSessionClaim: s.sessionID},
	}
}
