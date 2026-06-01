package state

import (
	"net/netip"
	"testing"

	"github.com/goccy/go-yaml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandCentralConfigDefaultsRouteTags(t *testing.T) {
	cfg := CentralCfg{
		Routers: []RouterCfg{{
			NodeCfg: NodeCfg{
				Id: "a",
				Prefixes: []PrefixHealthWrapper{{
					PrefixHealth: &StaticPrefixHealth{Prefix: netip.MustParsePrefix("10.0.0.0/24")},
				}},
			},
		}},
	}

	ExpandCentralConfig(&cfg)

	assert.Equal(t, DefaultRouteTag, cfg.Routers[0].Prefixes[0].GetTag())
}

func TestCentralConfigParsesRouteTags(t *testing.T) {
	var cfg CentralCfg
	err := yaml.Unmarshal([]byte(`
routers:
  - id: a
    prefixes:
      - type: static
        prefix: 10.0.0.0/24
        tag: custom
`), &cfg)
	require.NoError(t, err)

	ExpandCentralConfig(&cfg)

	assert.Equal(t, "custom", cfg.Routers[0].Prefixes[0].GetTag())
}

func routeTagCfg(clientTags ...string) *CentralCfg {
	return &CentralCfg{
		Routers: []RouterCfg{{
			NodeCfg: NodeCfg{
				Id: "exit",
				Prefixes: []PrefixHealthWrapper{{
					&StaticPrefixHealth{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Tag: "vpn"},
				}},
			},
		}},
		Clients: []ClientCfg{{
			NodeCfg: NodeCfg{
				Id:        "client1",
				Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.7")},
				RouteTags: clientTags,
			},
		}},
	}
}

func TestCentralConfigValidator_RouteTagAdvertised(t *testing.T) {
	assert.NoError(t, CentralConfigValidator(routeTagCfg("vpn", "main")))
}

func TestCentralConfigValidator_RouteTagUnknown(t *testing.T) {
	err := CentralConfigValidator(routeTagCfg("vpn", "ghost"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), `route_tag "ghost" is not advertised`)
}

func TestCentralConfigValidator_RouteTagMainAlwaysValid(t *testing.T) {
	// "main" is always a valid tag even when no prefix declares it explicitly.
	assert.NoError(t, CentralConfigValidator(routeTagCfg("main")))
}
