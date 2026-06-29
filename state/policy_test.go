package state

import (
	"net/netip"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// cfg builds a small two-customer + infra topology for policy tests.
func policyTestCfg() *CentralCfg {
	mkNode := func(id, ip string) NodeCfg {
		return NodeCfg{Id: NodeId(id), Addresses: []netip.Addr{addr(ip)}}
	}
	return &CentralCfg{
		Routers: []RouterCfg{
			{NodeCfg: mkNode("node-1", "10.100.200.1")},
			{NodeCfg: mkNode("node-2", "10.100.200.2")},
		},
		Clients: []ClientCfg{
			{NodeCfg: mkNode("cust-a", "10.100.200.50")},
			{NodeCfg: mkNode("cust-b", "10.100.200.51")},
		},
		Groups: map[string][]NodeId{
			"customers": {"cust-a", "cust-b"},
			"infra":     {"node-1", "node-2"},
		},
		Policy: []PolicyRule{
			{Src: []string{"group:customers"}, Dst: []string{"internet"}},
			{Src: []string{"group:infra"}, Dst: []string{"group:infra"}},
		},
	}
}

func TestPolicy_CustomerInternetOnly(t *testing.T) {
	p, err := CompilePolicy(policyTestCfg())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		src, dst string
		want     bool
	}{
		{"customer -> internet", "10.100.200.50", "8.8.8.8", true},
		{"customer -> other customer (isolated)", "10.100.200.50", "10.100.200.51", false},
		{"customer -> infra node", "10.100.200.50", "10.100.200.1", false},
		{"customer -> own gateway infra", "10.100.200.51", "10.100.200.2", false},
		{"infra -> infra", "10.100.200.1", "10.100.200.2", true},
		{"infra -> internet (no grant)", "10.100.200.1", "8.8.8.8", false},
		{"ungoverned source -> anything (legacy allow)", "10.100.200.99", "10.100.200.1", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := p.Allows(addr(c.src), addr(c.dst)); got != c.want {
				t.Fatalf("Allows(%s -> %s) = %v, want %v", c.src, c.dst, got, c.want)
			}
		})
	}
}

func TestPolicy_EmptyIsAllowAll(t *testing.T) {
	p, err := CompilePolicy(&CentralCfg{})
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allows(addr("10.0.0.1"), addr("10.0.0.2")) {
		t.Fatal("empty policy must allow all traffic")
	}
	// nil policy is also allow-all (data-plane safety before first apply).
	var nilp *CompiledPolicy
	if !nilp.Allows(addr("10.0.0.1"), addr("8.8.8.8")) {
		t.Fatal("nil policy must allow all traffic")
	}
}

func TestPolicy_InternetExcludesAdvertisedSubnet(t *testing.T) {
	cfg := policyTestCfg()
	// node-1 advertises an internal subnet; customers granted 'internet' must
	// still NOT reach it (it's part of the mesh space, not the internet).
	cfg.Routers[0].Prefixes = []PrefixHealthWrapper{
		{PrefixHealth: &StaticPrefixHealth{Prefix: netip.MustParsePrefix("192.168.10.0/24")}},
	}
	p, err := CompilePolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if p.Allows(addr("10.100.200.50"), addr("192.168.10.5")) {
		t.Fatal("customer reached an advertised internal subnet via 'internet' grant")
	}
	if !p.Allows(addr("10.100.200.50"), addr("1.1.1.1")) {
		t.Fatal("customer should still reach a public address")
	}
}

func TestPolicy_WildcardAndExplicitCIDR(t *testing.T) {
	cfg := policyTestCfg()
	cfg.Policy = []PolicyRule{
		{Src: []string{"cust-a"}, Dst: []string{"10.100.200.1/32"}}, // a may reach node-1 only
		{Src: []string{"node-1"}, Dst: []string{"*"}},               // node-1 may reach anything
	}
	p, err := CompilePolicy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Allows(addr("10.100.200.50"), addr("10.100.200.1")) {
		t.Fatal("cust-a -> node-1/32 should be allowed")
	}
	if p.Allows(addr("10.100.200.50"), addr("10.100.200.2")) {
		t.Fatal("cust-a -> node-2 should be denied")
	}
	if !p.Allows(addr("10.100.200.1"), addr("8.8.8.8")) {
		t.Fatal("node-1 -> * should be allowed")
	}
}

func TestPolicy_CompileErrors(t *testing.T) {
	bad := []PolicyRule{{Src: []string{"group:nope"}, Dst: []string{"internet"}}}
	if _, err := CompilePolicy(&CentralCfg{Policy: bad}); err == nil {
		t.Fatal("expected error for unknown group")
	}
	badDst := &CentralCfg{
		Clients: []ClientCfg{{NodeCfg: NodeCfg{Id: "c", Addresses: []netip.Addr{addr("10.0.0.1")}}}},
		Policy:  []PolicyRule{{Src: []string{"c"}, Dst: []string{"not-a-thing"}}},
	}
	if _, err := CompilePolicy(badDst); err == nil {
		t.Fatal("expected error for unknown destination selector")
	}
}
