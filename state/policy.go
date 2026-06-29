package state

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/gaissmai/bart"
)

// PROTOTYPE: Tailscale-style deny-by-default access policy.
//
// A PolicyRule permits traffic from any Src selector to any Dst selector.
// There is no "deny" action: anything not explicitly permitted is dropped for
// governed sources (see CompiledPolicy). Selectors:
//
//	"*"             any source / any destination
//	"group:<name>"  expands to the addresses of the group's members
//	"<node-id>"     the addresses of that router/client
//	"internet"      (dst only) any address outside the mesh (public IPs)
//	"<cidr>"        (dst only) an explicit prefix, e.g. 192.168.10.0/24
//
// Example (a paid-VPN customer pool that may only reach the internet, and is
// therefore isolated from every other client and all infrastructure):
//
//	groups:
//	  customers: [client20, client21]
//	  infra:     [node-1, node-2, node-3]
//	policy:
//	  - {src: [group:customers], dst: [internet]}
//	  - {src: [group:infra],     dst: [group:infra]}
type PolicyRule struct {
	Src []string `yaml:"src"`
	Dst []string `yaml:"dst"`
}

// CompiledPolicy is the data-plane view of the access policy, consulted per
// packet. A source becomes "governed" the moment it appears as a Src in any
// rule; governed sources are deny-by-default while ungoverned sources are left
// untouched (legacy allow-all). This keeps the prototype from black-holing
// mesh/control traffic in deployments that haven't written any policy yet, and
// lets you opt a client into isolation simply by naming it in a rule.
type CompiledPolicy struct {
	bySrc       map[netip.Addr]*dstSet // governed source -> permitted destinations
	anySrc      *dstSet                // rules with Src "*"
	allGoverned bool                   // a rule used Src "*": every source is governed
	meshSpace   *bart.Table[struct{}]  // in-mesh prefixes; "internet" == outside this
}

type dstSet struct {
	any      bool
	internet bool
	prefixes *bart.Table[struct{}]
}

func newDstSet() *dstSet {
	return &dstSet{prefixes: &bart.Table[struct{}]{}}
}

func (d *dstSet) allows(dst netip.Addr, isInternet func(netip.Addr) bool) bool {
	if d.any {
		return true
	}
	if _, ok := d.prefixes.Lookup(dst); ok {
		return true
	}
	return d.internet && isInternet(dst)
}

// Allows reports whether a packet from src to dst is permitted. Ungoverned
// sources (those never named as a rule Src) are always allowed, so an empty
// policy is a no-op.
func (p *CompiledPolicy) Allows(src, dst netip.Addr) bool {
	if p == nil {
		return true
	}
	src, dst = src.Unmap(), dst.Unmap()
	ds, governed := p.bySrc[src]
	if !p.allGoverned && !governed {
		return true
	}
	if governed && ds.allows(dst, p.isInternet) {
		return true
	}
	if p.anySrc != nil && p.anySrc.allows(dst, p.isInternet) {
		return true
	}
	return false
}

func (p *CompiledPolicy) isInternet(dst netip.Addr) bool {
	if p.meshSpace == nil {
		return true
	}
	_, inMesh := p.meshSpace.Lookup(dst)
	return !inMesh
}

// CompilePolicy builds the data-plane policy from the central config. It fails
// closed on unknown selectors (so a typo is surfaced at apply time rather than
// silently widening access).
func CompilePolicy(cfg *CentralCfg) (*CompiledPolicy, error) {
	nodeAddrs := make(map[NodeId][]netip.Addr)
	for _, node := range cfg.GetNodes() {
		for _, addr := range node.Addresses {
			nodeAddrs[node.Id] = append(nodeAddrs[node.Id], addr.Unmap())
		}
	}

	// meshSpace: every node/client address plus any non-default advertised
	// prefix. A destination outside this set is "internet".
	meshSpace := &bart.Table[struct{}]{}
	for _, addrs := range nodeAddrs {
		for _, a := range addrs {
			meshSpace.Insert(netip.PrefixFrom(a, a.BitLen()), struct{}{})
		}
	}
	for _, pfx := range cfg.GetPrefixes() {
		if pfx.Bits() > 0 { // skip default routes (0.0.0.0/0, ::/0)
			meshSpace.Insert(pfx.Masked(), struct{}{})
		}
	}

	p := &CompiledPolicy{
		bySrc:     make(map[netip.Addr]*dstSet),
		meshSpace: meshSpace,
	}

	resolveGroup := func(name string) ([]netip.Addr, error) {
		members, ok := cfg.Groups[name]
		if !ok {
			return nil, fmt.Errorf("unknown group %q", name)
		}
		var out []netip.Addr
		for _, id := range members {
			addrs, ok := nodeAddrs[id]
			if !ok {
				return nil, fmt.Errorf("group %q references unknown node %q", name, id)
			}
			out = append(out, addrs...)
		}
		return out, nil
	}

	// resolveMembers expands a "group:<name>" or bare "<node-id>" selector to
	// its addresses; shared by src and dst resolution.
	resolveMembers := func(sel string) ([]netip.Addr, error) {
		if name, ok := strings.CutPrefix(sel, "group:"); ok {
			return resolveGroup(name)
		}
		if addrs, ok := nodeAddrs[NodeId(sel)]; ok {
			return addrs, nil
		}
		return nil, fmt.Errorf("unknown selector %q", sel)
	}

	for ri, rule := range cfg.Policy {
		// Resolve the targets this rule's destinations are merged into.
		var targets []*dstSet
		for _, sel := range rule.Src {
			switch {
			case sel == "*":
				if p.anySrc == nil {
					p.anySrc = newDstSet()
				}
				p.allGoverned = true
				targets = append(targets, p.anySrc)
			case sel == "internet":
				return nil, fmt.Errorf("rule %d: 'internet' is not valid as a src", ri)
			default:
				addrs, err := resolveMembers(sel)
				if err != nil {
					return nil, fmt.Errorf("rule %d src: %w", ri, err)
				}
				for _, a := range addrs {
					ds := p.bySrc[a]
					if ds == nil {
						ds = newDstSet()
						p.bySrc[a] = ds
					}
					targets = append(targets, ds)
				}
			}
		}

		for _, sel := range rule.Dst {
			if err := applyDstSelector(sel, targets, resolveMembers); err != nil {
				return nil, fmt.Errorf("rule %d dst: %w", ri, err)
			}
		}
	}

	return p, nil
}

func applyDstSelector(sel string, targets []*dstSet, resolveMembers func(string) ([]netip.Addr, error)) error {
	switch sel {
	case "*":
		for _, t := range targets {
			t.any = true
		}
		return nil
	case "internet":
		for _, t := range targets {
			t.internet = true
		}
		return nil
	}
	if pfx, err := netip.ParsePrefix(sel); err == nil {
		for _, t := range targets {
			t.prefixes.Insert(pfx.Masked(), struct{}{})
		}
		return nil
	}
	// group:<name> or a bare node id
	addrs, err := resolveMembers(sel)
	if err != nil {
		return fmt.Errorf("%w (expected '*', 'internet', 'group:<name>', a node id, or a CIDR)", err)
	}
	insertAddrs(targets, addrs)
	return nil
}

func insertAddrs(targets []*dstSet, addrs []netip.Addr) {
	for _, a := range addrs {
		a = a.Unmap()
		pfx := netip.PrefixFrom(a, a.BitLen())
		for _, t := range targets {
			t.prefixes.Insert(pfx, struct{}{})
		}
	}
}
