package core

import (
	"net/netip"
	"time"

	"github.com/encodeous/nylon/polyamide/device"
	"github.com/gaissmai/bart"
	"go4.org/netipx"
	"google.golang.org/protobuf/proto"

	"github.com/encodeous/nylon/log"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"github.com/jellydator/ttlcache/v3"
)

type RouteTableEntry struct {
	Nh        state.NodeId
	Peer      *device.Peer
	Blackhole bool
	Tag       string
}

func (n *Nylon) GetNeighIO(neigh state.NodeId) *IOPending {
	nio, ok := n.router.IO[neigh]
	if !ok {
		nio = &IOPending{
			SeqnoReq:   make(map[state.Source]state.Pair[uint16, uint8]),
			SeqnoDedup: ttlcache.New[state.Source, uint16](ttlcache.WithTTL[state.Source, uint16](n.SeqnoDedupTTL), ttlcache.WithDisableTouchOnHit[state.Source, uint16]()),
			Acks:       make(map[state.RouteKey]struct{}),
			Updates:    make(map[state.RouteKey]*protocol.Ny_Update),
		}
		n.router.IO[neigh] = nio
	}
	n.router.IO[neigh] = nio
	return nio
}

func (n *Nylon) SendRouteUpdate(neigh state.NodeId, advRoute state.PubRoute) {
	nio := n.GetNeighIO(neigh)
	prefix, _ := advRoute.Prefix.MarshalBinary()
	nio.Updates[advRoute.Source.Key()] = &protocol.Ny_Update{
		RouterId: string(advRoute.NodeId),
		Prefix:   prefix,
		Seqno:    uint32(advRoute.Seqno),
		Metric:   advRoute.Metric,
		Tag:      state.WireRouteTag(advRoute.Tag),
	}
}

func (n *Nylon) SendAckRetract(neigh state.NodeId, key state.RouteKey) {
	nio := n.GetNeighIO(neigh)
	nio.Acks[key] = struct{}{}
}

func (n *Nylon) BroadcastSendRouteUpdate(advRoute state.PubRoute) {
	for _, neigh := range n.RouterState.Neighbours {
		n.SendRouteUpdate(neigh.Id, advRoute)
	}
}

func (n *Nylon) RequestSeqno(neigh state.NodeId, src state.Source, seqno uint16, hopCnt uint8) {
	nio := n.GetNeighIO(neigh)
	old := nio.SeqnoDedup.Get(src)
	maxSeq := seqno
	if old != nil {
		maxSeq = max(seqno, old.Value())
		if SeqnoGe(old.Value(), seqno) {
			return // we have already sent such a request before
		}
	}
	nio.SeqnoDedup.Set(src, maxSeq, ttlcache.DefaultTTL)
	req, ok := nio.SeqnoReq[src]
	if !ok || seqno < req.V1 {
		req = state.Pair[uint16, uint8]{V1: seqno, V2: hopCnt}
	} else {
		if hopCnt > req.V2 {
			req.V2 = hopCnt
		}
	}
	nio.SeqnoReq[src] = req
}

func (n *Nylon) BroadcastRequestSeqno(src state.Source, seqno uint16, hopCnt uint8) {
	for _, neigh := range n.RouterState.Neighbours {
		n.RequestSeqno(neigh.Id, src, seqno, hopCnt)
	}
}

func (n *Nylon) RouterEvent(event string, desc string, args ...any) {
	if event == log.EventNoEndpointToNeigh {
		return // ignored
	}
	n.router.log.Debug(desc, append([]any{"event", event}, args...)...)
}

func (n *Nylon) UpdateNeighbour(neigh state.NodeId) {
	PushFullTable(n.RouterState, n, neigh)
}

func (n *Nylon) TableInsertRoute(key state.RouteKey, route state.SelRoute) {
	nh := route.Nh
	nf := n.cloneForwardTable(key.Tag)
	ne := n.router.ExitTable.Load().Clone()
	if route.Metric == state.INF {
		nf.Insert(key.Prefix, RouteTableEntry{
			Nh:        nh,
			Blackhole: true,
			Tag:       key.Tag,
		})
		ne.Delete(key.Prefix)
		n.storeForwardTable(key.Tag, nf)
		n.router.ExitTable.Store(ne)
		return
	}
	peer := n.Device.LookupPeer(device.NoisePublicKey(n.GetNode(nh).PubKey))
	nf.Insert(key.Prefix, RouteTableEntry{
		Nh:   nh,
		Peer: peer,
		Tag:  key.Tag,
	})
	if route.Nh == n.LocalCfg.Id {
		ne.Insert(key.Prefix, RouteTableEntry{
			Nh:   nh,
			Peer: peer,
			Tag:  key.Tag,
		})
	} else {
		ne.Delete(key.Prefix)
	}
	n.storeForwardTable(key.Tag, nf)
	n.router.ExitTable.Store(ne)
}

func (n *Nylon) TableDeleteRoute(key state.RouteKey) {
	nf := n.cloneForwardTable(key.Tag)
	ne := n.router.ExitTable.Load().Clone()
	nf.Delete(key.Prefix)
	ne.Delete(key.Prefix)
	n.storeForwardTable(key.Tag, nf)
	n.router.ExitTable.Store(ne)
}

// cloneForwardTable returns a writable clone of the forwarding table for tag (the
// main table for the default tag, an existing or fresh tagged table otherwise).
func (n *Nylon) cloneForwardTable(tag string) *bart.Table[RouteTableEntry] {
	if existing := n.forwardTable(tag); existing != nil {
		return existing.Clone()
	}
	return &bart.Table[RouteTableEntry]{}
}

// storeForwardTable atomically publishes tbl as the forwarding table for tag.
func (n *Nylon) storeForwardTable(tag string, tbl *bart.Table[RouteTableEntry]) {
	if state.NormalizeRouteTag(tag) == state.DefaultRouteTag {
		n.router.ForwardTable.Store(tbl)
		return
	}
	tag = state.NormalizeRouteTag(tag)
	cur := *n.router.TaggedForwardTables.Load()
	next := make(map[string]*bart.Table[RouteTableEntry], len(cur)+1)
	for t, x := range cur {
		next[t] = x
	}
	next[tag] = tbl
	n.router.TaggedForwardTables.Store(&next)
}

// forwardTable returns the forwarding table for tag (the main table for the default
// tag), or nil if no tagged table has been created for a non-default tag yet.
func (n *Nylon) forwardTable(tag string) *bart.Table[RouteTableEntry] {
	if state.NormalizeRouteTag(tag) == state.DefaultRouteTag {
		return n.router.ForwardTable.Load()
	}
	return (*n.router.TaggedForwardTables.Load())[state.NormalizeRouteTag(tag)]
}

type IOPending struct {
	// SeqnoReq values represent a pair of (seqno, hop count)
	SeqnoReq   map[state.Source]state.Pair[uint16, uint8]
	SeqnoDedup *ttlcache.Cache[state.Source, uint16]
	Acks       map[state.RouteKey]struct{}
	Updates    map[state.RouteKey]*protocol.Ny_Update
}

func (n *Nylon) CleanupRouter() error {
	n.router.log = nil
	n.router.IO = nil
	return nil
}

func (n *Nylon) GcRouter() error {
	RunGC(n.RouterState, n)
	for id, _ := range n.router.IO {
		if n.RouterState.GetNeighbour(id) == nil {
			delete(n.router.IO, id)
			continue
		}
	}
	for _, nio := range n.router.IO {
		nio.SeqnoDedup.DeleteExpired()
	}
	return nil
}

func (n *Nylon) InitRouter() error {
	n.router.log = n.Log.With("module", log.ScopeRouter)
	n.router.log.Debug("init router")
	n.router.IO = make(map[state.NodeId]*IOPending)
	n.router.ForwardTable.Store(&bart.Table[RouteTableEntry]{})
	n.router.TaggedForwardTables.Store(&map[string]*bart.Table[RouteTableEntry]{})
	n.router.ExitTable.Store(&bart.Table[RouteTableEntry]{})
	n.router.SrcTags.Store(&map[netip.Addr][]string{})
	n.router.UnderlayAddrs.Store(&map[netip.Addr]struct{}{})
	n.RouterState = &state.RouterState{
		RouterTunables: &n.RouterTunables,
		Id:             n.LocalCfg.Id,
		SelfSeqno:      make(map[state.RouteKey]uint16),
		Routes:         make(map[state.RouteKey]state.SelRoute),
		Sources:        make(map[state.Source]state.FD),
		Neighbours:     make([]*state.Neighbour, 0),
		Advertised:     make(map[state.RouteKey]state.Advertisement),
	}
	n.storeAccessPolicy(&n.CentralCfg) // compile & enforce the startup policy (fail-soft to allow-all)
	maxTime := time.Unix(1<<63-62135596801, 999999999)
	for _, prefix := range n.GetRouter(n.LocalCfg.Id).Prefixes {
		n.RouterState.Advertised[state.NewRouteKey(prefix.GetPrefix(), prefix.GetTag())] = state.Advertisement{
			NodeId:        n.LocalCfg.Id,
			Expiry:        maxTime,
			IsPassiveHold: false,
			MetricFn:      prefix.GetMetric,
		}
	}

	n.router.log.Debug("schedule router tasks")

	n.RepeatTask(func() error {
		FullTableUpdate(n.RouterState, n)
		return nil
	}, n.RouteUpdateDelay)
	n.RepeatTask(func() error {
		SolveStarvation(n.RouterState, n)
		return nil
	}, n.StarvationDelay)

	n.RepeatTask(func() error {
		return n.flushIO()
	}, n.NeighbourIOFlushDelay)
	return nil
}

// ComputeSysRouteTable computes: computed = prefixes - (((n.CentralCfg.ExcludeIPs U selected self prefixes) - n.LocalCfg.UnexcludeIPs) U n.LocalCfg.ExcludeIPs)
func (n *Nylon) ComputeSysRouteTable() []netip.Prefix {
	prefixes := make([]netip.Prefix, 0)
	selectedSelf := make([]netip.Prefix, 0)
	// The OS routing table only mirrors the default (main) topology. Tagged
	// topologies are reachable solely through nylon's policy-based forwarding.
	for key, route := range n.RouterState.Routes {
		if key.Tag != state.DefaultRouteTag || route.Metric == state.INF {
			continue
		}
		prefixes = append(prefixes, key.Prefix)
		if route.Nh == n.LocalCfg.Id {
			selectedSelf = append(selectedSelf, key.Prefix)
		}
	}

	excludes := netipx.IPSetBuilder{}
	excludes.AddSet(state.MakeSet(n.CentralCfg.ExcludeIPs))
	excludes.AddSet(state.MakeSet(selectedSelf))
	excludes.RemoveSet(state.MakeSet(n.LocalCfg.UnexcludeIPs))
	excludes.AddSet(state.MakeSet(n.LocalCfg.ExcludeIPs))

	excludedSet, _ := excludes.IPSet()
	final := netipx.IPSetBuilder{}
	final.AddSet(state.MakeSet(prefixes))
	final.RemoveSet(excludedSet)
	res, _ := final.IPSet()
	return res.Prefixes()
}

func (n *Nylon) updatePassiveClient(prefix state.PrefixHealthWrapper, node state.NodeId, passiveHold bool) {
	// inserts an artificial route into the table

	hasPassiveHold := false
	key := state.NewRouteKey(prefix.GetPrefix(), prefix.GetTag())
	old, ok := n.RouterState.Advertised[key]
	if ok && old.NodeId == node {
		hasPassiveHold = old.IsPassiveHold
	}

	if passiveHold && !hasPassiveHold {
		// the first time we enter passive hold, we should increment the seqno to prevent other nodes from switching away from the route
		// this reduces a lot of route flapping when the client wakes up, sends some traffic and then goes back to sleep
		n.RouterState.SetSeqno(key, n.RouterState.GetSeqno(key)+1)
	}

	// passive nodes may only have static prefixes, so we don't call prefix.Start()
	n.RouterState.Advertised[key] = state.Advertisement{
		NodeId:        node,
		Expiry:        time.Now().Add(n.ClientKeepaliveInterval),
		IsPassiveHold: passiveHold,
		MetricFn:      prefix.GetMetric,
		ExpiryFn: func() {
			// we didn't start the prefix monitoring
		},
	}
}

func (n *Nylon) hasRecentlyAdvertised(key state.RouteKey) bool {
	adv, ok := n.RouterState.Advertised[key]
	if !ok {
		return false
	}
	return time.Now().Before(adv.Expiry)
}

func (n *Nylon) checkNeigh(id state.NodeId) bool {
	for _, node := range n.RouterState.Neighbours {
		if node.Id == id {
			return true
		}
	}
	n.router.log.Warn("received packet from unknown neighbour", "from", id)
	return false
}

func (n *Nylon) checkPrefix(prefix netip.Prefix) bool {
	for _, p := range n.GetPrefixes() {
		if p == prefix {
			return true
		}
	}
	n.router.log.Warn("received packet for unknown prefix", "prefix", prefix)
	return false
}

func (n *Nylon) checkNode(id state.NodeId) bool {
	ncfg := n.TryGetNode(id)
	if ncfg == nil {
		n.router.log.Warn("received packet from unknown node", "from", id)
	}
	return ncfg != nil
}

// packet handlers
func (n *Nylon) routerHandleRouteUpdate(node state.NodeId, update *protocol.Ny_Update) error {
	prefix := netip.Prefix{}
	err := prefix.UnmarshalBinary(update.Prefix)
	if err != nil {
		n.router.log.Warn("received update with invalid prefix", "prefix", update.Prefix, "err", err)
		return nil
	}
	if !n.checkNeigh(node) ||
		!n.checkPrefix(prefix) ||
		!n.checkNode(state.NodeId(update.RouterId)) {
		return nil
	}
	HandleNeighbourUpdate(n.RouterState, n, node, state.PubRoute{
		Source: state.Source{
			NodeId: state.NodeId(update.RouterId),
			Prefix: prefix,
			Tag:    state.NormalizeRouteTag(update.Tag),
		},
		FD: state.FD{
			Seqno:  uint16(update.Seqno),
			Metric: update.Metric,
		},
	})
	ComputeRoutes(n.RouterState, n)
	return nil
}

func (n *Nylon) routerHandleAckRetract(neigh state.NodeId, update *protocol.Ny_AckRetract) error {
	prefix := netip.Prefix{}
	err := prefix.UnmarshalBinary(update.Prefix)
	if err != nil {
		n.router.log.Warn("received ack retract with invalid prefix", "prefix", update.Prefix, "err", err)
		return nil
	}
	if !n.checkPrefix(prefix) ||
		!n.checkNeigh(neigh) {
		return nil
	}
	HandleAckRetract(n.RouterState, n, neigh, state.NewRouteKey(prefix, update.Tag))
	return nil
}

func (n *Nylon) routerHandleSeqnoRequest(neigh state.NodeId, pkt *protocol.Ny_SeqnoRequest) error {
	prefix := netip.Prefix{}
	err := prefix.UnmarshalBinary(pkt.Prefix)
	if err != nil {
		n.router.log.Warn("received seqno request with invalid prefix", "prefix", pkt.Prefix, "err", err)
		return nil
	}
	if !n.checkNeigh(neigh) ||
		!n.checkPrefix(prefix) ||
		!n.checkNode(state.NodeId(pkt.RouterId)) {
		return nil
	}
	HandleSeqnoRequest(n.RouterState, n, neigh, state.Source{
		NodeId: state.NodeId(pkt.RouterId),
		Prefix: prefix,
		Tag:    state.NormalizeRouteTag(pkt.Tag),
	}, uint16(pkt.Seqno), uint8(pkt.HopCount))
	return nil
}

func (n *Nylon) flushIO() error {
	for _, neigh := range n.RouterState.Neighbours {
		// TODO, investigate effect of packet loss on control messages
		best := neigh.BestEndpoint()
		nio := n.GetNeighIO(neigh.Id)
		if nio == nil {
			continue
		}
		if best != nil && best.IsActive() {
			peer := n.Device.LookupPeer(device.NoisePublicKey(n.GetNode(neigh.Id).PubKey))
			for {
				bundle := &protocol.TransportBundle{}
				tLength := 0

				// we can coalesce messages, but we need to make sure we don't fragment our UDP packet
				// if a single proto message is somehow larger than SafeMTU, we still send it, but it will get fragmented

				for seqR, _ := range nio.SeqnoReq {
					prefixBytes, _ := seqR.Prefix.MarshalBinary()
					req := &protocol.Ny{Type: &protocol.Ny_SeqnoRequestOp{
						SeqnoRequestOp: &protocol.Ny_SeqnoRequest{
							RouterId: string(seqR.NodeId),
							Prefix:   prefixBytes,
							Seqno:    uint32(nio.SeqnoReq[seqR].V1),
							HopCount: uint32(nio.SeqnoReq[seqR].V2),
							Tag:      state.WireRouteTag(seqR.Tag),
						},
					}}
					if tLength != 0 && tLength+proto.Size(req) >= n.SafeMTU {
						goto send
					}
					delete(nio.SeqnoReq, seqR)
					bundle.Packets = append(bundle.Packets, req)
					tLength += proto.Size(req)
				}

				for id, update := range nio.Updates {
					req := &protocol.Ny{Type: &protocol.Ny_RouteOp{
						RouteOp: update,
					}}
					if tLength != 0 && tLength+proto.Size(req) >= n.SafeMTU {
						goto send
					}
					delete(nio.Updates, id)
					bundle.Packets = append(bundle.Packets, req)
					tLength += proto.Size(req)
				}

				for key := range nio.Acks {
					prefixBytes, _ := key.Prefix.MarshalBinary()
					req := &protocol.Ny{Type: &protocol.Ny_AckRetractOp{
						AckRetractOp: &protocol.Ny_AckRetract{
							Prefix: prefixBytes,
							Tag:    state.WireRouteTag(key.Tag),
						},
					}}
					if tLength != 0 && tLength+proto.Size(req) >= n.SafeMTU {
						goto send
					}
					delete(nio.Acks, key)
					bundle.Packets = append(bundle.Packets, req)
					tLength += proto.Size(req)
				}

				if tLength == 0 {
					break
				}
			send:
				err := n.SendNylonBundle(bundle, nil, peer)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}
