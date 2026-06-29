package core

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
)

func TestComputeSysRouteTableAppliesExcludesAndUnexcludes(t *testing.T) {
	n := sysRouteTestNylon(
		"a",
		[]netip.Prefix{
			pfx("10.0.0.128/25"),
		},
		[]netip.Prefix{
			pfx("10.0.1.64/26"),
		},
		[]netip.Prefix{
			pfx("10.0.2.0/25"),
		},
		map[netip.Prefix]state.SelRoute{
			pfx("10.0.0.0/24"): {Nh: "b"},
			pfx("10.0.1.0/24"): {Nh: "a"},
			pfx("10.0.2.0/24"): {Nh: "c"},
		},
	)

	assert.ElementsMatch(t, []netip.Prefix{
		pfx("10.0.0.0/25"),
		pfx("10.0.1.64/26"),
		pfx("10.0.2.128/25"),
	}, n.ComputeSysRouteTable())
}

func TestComputeSysRouteTableLocalExcludeOverridesUnexclude(t *testing.T) {
	n := sysRouteTestNylon(
		"a",
		[]netip.Prefix{
			pfx("10.0.0.0/24"),
		},
		[]netip.Prefix{
			pfx("10.0.0.0/25"),
		},
		[]netip.Prefix{
			pfx("10.0.0.64/26"),
		},
		map[netip.Prefix]state.SelRoute{
			pfx("10.0.0.0/24"): {Nh: "b"},
		},
	)

	assert.ElementsMatch(t, []netip.Prefix{
		pfx("10.0.0.0/26"),
	}, n.ComputeSysRouteTable())
}

func TestComputeSysRouteTableDoesNotMutateCentralExcludes(t *testing.T) {
	centralExcludes := make([]netip.Prefix, 1, 4)
	centralExcludes[0] = pfx("10.0.0.0/25")
	n := sysRouteTestNylon(
		"a",
		centralExcludes,
		nil,
		nil,
		map[netip.Prefix]state.SelRoute{
			pfx("10.0.1.0/24"): {Nh: "a"},
		},
	)

	_ = n.ComputeSysRouteTable()

	assert.Equal(t, []netip.Prefix{pfx("10.0.0.0/25")}, n.CentralCfg.ExcludeIPs)
}

func TestComputeSysRouteTableCoalescesAdjacentResults(t *testing.T) {
	n := sysRouteTestNylon(
		"a",
		nil,
		nil,
		nil,
		map[netip.Prefix]state.SelRoute{
			pfx("10.0.0.0/25"):   {Nh: "b"},
			pfx("10.0.0.128/25"): {Nh: "b"},
		},
	)

	assert.Equal(t, []netip.Prefix{pfx("10.0.0.0/24")}, sortedPrefixes(n.ComputeSysRouteTable()))
}

func TestComputeSysRouteTableExcludesTaggedRoutes(t *testing.T) {
	// The OS routing table only mirrors the default (main) topology. Routes that
	// exist solely under a non-default tag are reachable through policy-based
	// forwarding only, and must not be installed as system routes.
	n := sysRouteTestNylon(
		"b",
		nil,
		nil,
		nil,
		map[netip.Prefix]state.SelRoute{},
	)
	n.CentralCfg.Routers = []state.RouterCfg{{
		NodeCfg: state.NodeCfg{
			Id: "b",
		},
	}}
	n.RouterState.Routes = map[state.RouteKey]state.SelRoute{
		state.NewRouteKey(pfx("10.50.0.0/24"), "vpn"): {
			PubRoute: state.PubRoute{Source: state.Source{NodeId: "a", Prefix: pfx("10.50.0.0/24"), Tag: "vpn"}},
			Nh:       "a",
		},
		state.NewRouteKey(pfx("10.60.0.0/24"), state.DefaultRouteTag): {
			PubRoute: state.PubRoute{Source: state.Source{NodeId: "a", Prefix: pfx("10.60.0.0/24")}},
			Nh:       "a",
		},
	}
	assert.Equal(t, []netip.Prefix{pfx("10.60.0.0/24")}, n.ComputeSysRouteTable())
}

func sysRouteTestNylon(local state.NodeId, centralExcludes, localUnexcludes, localExcludes []netip.Prefix, routes map[netip.Prefix]state.SelRoute) *Nylon {
	keyedRoutes := make(map[state.RouteKey]state.SelRoute, len(routes))
	for prefix, route := range routes {
		key := state.NewRouteKey(prefix, state.DefaultRouteTag)
		if route.Tag == "" {
			route.Tag = state.DefaultRouteTag
		}
		route.Prefix = prefix
		keyedRoutes[key] = route
	}
	return &Nylon{
		ConfigState: state.ConfigState{
			CentralCfg: state.CentralCfg{
				ExcludeIPs: centralExcludes,
			},
			LocalCfg: state.LocalCfg{
				Id:           local,
				UnexcludeIPs: localUnexcludes,
				ExcludeIPs:   localExcludes,
			},
		},
		RouterState: &state.RouterState{
			Routes: keyedRoutes,
		},
	}
}

func pfx(s string) netip.Prefix {
	return netip.MustParsePrefix(s)
}

func sortedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	slices.SortFunc(prefixes, func(a, b netip.Prefix) int {
		return a.Compare(b)
	})
	return prefixes
}
