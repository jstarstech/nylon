package core

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type noopRouter struct{}

func (noopRouter) SendRouteUpdate(state.NodeId, state.PubRoute)           {}
func (noopRouter) SendAckRetract(state.NodeId, state.RouteKey)            {}
func (noopRouter) BroadcastSendRouteUpdate(state.PubRoute)                {}
func (noopRouter) RequestSeqno(state.NodeId, state.Source, uint16, uint8) {}
func (noopRouter) BroadcastRequestSeqno(state.Source, uint16, uint8)      {}
func (noopRouter) TableInsertRoute(state.RouteKey, state.SelRoute)        {}
func (noopRouter) TableDeleteRoute(state.RouteKey)                        {}
func (noopRouter) RouterEvent(event string, desc string, args ...any)     {}

func TestRouteUpdateWireTagDefaults(t *testing.T) {
	n := &Nylon{}
	n.router.IO = make(map[state.NodeId]*IOPending)
	n.SeqnoDedupTTL = time.Minute
	prefix := netip.MustParsePrefix("10.0.0.0/24")

	n.SendRouteUpdate("b", state.PubRoute{
		Source: state.Source{NodeId: "a", Prefix: prefix, Tag: state.DefaultRouteTag},
		FD:     state.FD{Seqno: 1, Metric: 2},
	})
	mainUpdate := n.router.IO["b"].Updates[state.NewRouteKey(prefix, state.DefaultRouteTag)]
	require.NotNil(t, mainUpdate)
	assert.Empty(t, mainUpdate.Tag)

	n.SendRouteUpdate("b", state.PubRoute{
		Source: state.Source{NodeId: "a", Prefix: prefix, Tag: "custom"},
		FD:     state.FD{Seqno: 1, Metric: 2},
	})
	customUpdate := n.router.IO["b"].Updates[state.NewRouteKey(prefix, "custom")]
	require.NotNil(t, customUpdate)
	assert.Equal(t, "custom", customUpdate.Tag)

	wire := &protocol.Ny{Type: &protocol.Ny_RouteOp{RouteOp: customUpdate}}
	data, err := proto.Marshal(wire)
	require.NoError(t, err)
	var decoded protocol.Ny
	require.NoError(t, proto.Unmarshal(data, &decoded))
	assert.Equal(t, "custom", decoded.GetRouteOp().GetTag())
}

func TestNormalizeRouteTags(t *testing.T) {
	// empty -> main, de-duped, order preserved
	assert.Equal(t, []string{"vpn", state.DefaultRouteTag}, normalizeRouteTags([]string{"vpn", "", "vpn", "main"}))
	assert.Equal(t, []string{state.DefaultRouteTag}, normalizeRouteTags([]string{"main"}))
	assert.Empty(t, normalizeRouteTags(nil))
}

func TestResolveRouteTagsMapsNodeAddresses(t *testing.T) {
	n := &Nylon{}
	n.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	n.router.SrcTags.Store(&map[netip.Addr][]string{})
	n.CentralCfg = state.CentralCfg{
		Clients: []state.ClientCfg{{
			NodeCfg: state.NodeCfg{
				Id:        "client1",
				Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.7")},
				RouteTags: []string{"vpn", "main"},
			},
		}},
		Routers: []state.RouterCfg{{
			NodeCfg: state.NodeCfg{Id: "plain", Addresses: []netip.Addr{netip.MustParseAddr("10.0.0.8")}},
		}},
	}

	n.resolveRouteTags()

	srcTags := *n.router.SrcTags.Load()
	assert.Equal(t, []string{"vpn", state.DefaultRouteTag}, srcTags[netip.MustParseAddr("10.0.0.7")])
	_, tagged := srcTags[netip.MustParseAddr("10.0.0.8")]
	assert.False(t, tagged, "nodes without route_tags must not be steered")
}

func TestVanillaRouteUpdateUsesMainRouteKey(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	tunables := state.DefaultRouterTunables()
	rs := &state.RouterState{
		RouterTunables: &tunables,
		Id:             "local",
		SelfSeqno:      make(map[state.RouteKey]uint16),
		Routes:         make(map[state.RouteKey]state.SelRoute),
		Sources:        make(map[state.Source]state.FD),
		Neighbours: []*state.Neighbour{{
			Id:     "b",
			Routes: make(map[state.RouteKey]state.NeighRoute),
		}},
		Advertised: make(map[state.RouteKey]state.Advertisement),
	}

	HandleNeighbourUpdate(rs, noopRouter{}, "b", state.PubRoute{
		Source: state.Source{NodeId: "a", Prefix: prefix},
		FD:     state.FD{Seqno: 1, Metric: 2},
	})

	_, ok := rs.GetNeighbour("b").Routes[state.NewRouteKey(prefix, "")]
	assert.True(t, ok)
}
