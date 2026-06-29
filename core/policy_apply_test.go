package core

import (
	"log/slog"
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

func policyTestNylon() *Nylon {
	return &Nylon{Log: slog.New(slog.DiscardHandler)}
}

func pAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// a customer client that may only reach the internet, plus one infra router.
func policyApplyCfg() *state.CentralCfg {
	return &state.CentralCfg{
		Routers: []state.RouterCfg{
			{NodeCfg: state.NodeCfg{Id: "node-1", Addresses: []netip.Addr{pAddr("10.0.0.1")}}},
		},
		Clients: []state.ClientCfg{
			{NodeCfg: state.NodeCfg{Id: "cust", Addresses: []netip.Addr{pAddr("10.0.0.50")}}},
		},
		Policy: []state.PolicyRule{
			{Src: []string{"cust"}, Dst: []string{"internet"}},
		},
	}
}

var badPolicyCfg = &state.CentralCfg{
	Policy: []state.PolicyRule{{Src: []string{"group:nope"}, Dst: []string{"internet"}}},
}

// The startup path compiles and enforces the configured policy. Previously
// InitRouter installed allow-all and the policy only took effect after the
// first *distributed config change*, so a static deployment never enforced.
func TestStoreAccessPolicy_StartupEnforces(t *testing.T) {
	n := policyTestNylon()
	n.storeAccessPolicy(policyApplyCfg())

	p := n.router.Policy.Load()
	if assert.NotNil(t, p) {
		assert.False(t, p.Allows(pAddr("10.0.0.50"), pAddr("10.0.0.1")), "governed customer must be denied to mesh infra")
		assert.True(t, p.Allows(pAddr("10.0.0.50"), pAddr("8.8.8.8")), "customer may reach the internet")
		assert.True(t, p.Allows(pAddr("10.0.0.1"), pAddr("10.0.0.50")), "ungoverned source stays allow-all")
	}
}

// A bad policy at startup (no previous policy) fails open to allow-all rather
// than leaving a nil policy or black-holing the node. Bad policy is normally
// rejected at the validation gate; this is defence in depth.
func TestStoreAccessPolicy_StartupBadFailsOpen(t *testing.T) {
	n := policyTestNylon()
	n.storeAccessPolicy(badPolicyCfg)

	p := n.router.Policy.Load()
	if assert.NotNil(t, p, "startup fallback policy must be installed") {
		assert.True(t, p.Allows(pAddr("10.0.0.50"), pAddr("10.0.0.1")), "fallback must be allow-all")
	}
}

// A bad policy applied after a good one keeps the previous (good) policy.
func TestStoreAccessPolicy_KeepsPreviousOnError(t *testing.T) {
	n := policyTestNylon()
	n.storeAccessPolicy(policyApplyCfg())
	n.storeAccessPolicy(badPolicyCfg)

	p := n.router.Policy.Load()
	assert.False(t, p.Allows(pAddr("10.0.0.50"), pAddr("10.0.0.1")), "previous enforcing policy must be retained")
}
