package state

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type NodeId string

const DefaultRouteTag = "main"

// RouteKey identifies a route within one tagged routing topology.
type RouteKey struct {
	Prefix netip.Prefix
	Tag    string
}

func NewRouteKey(prefix netip.Prefix, tag string) RouteKey {
	return RouteKey{
		Prefix: prefix,
		Tag:    NormalizeRouteTag(tag),
	}
}

func (k RouteKey) String() string {
	if NormalizeRouteTag(k.Tag) == DefaultRouteTag {
		return k.Prefix.String()
	}
	return fmt.Sprintf("%s@%s", k.Prefix, NormalizeRouteTag(k.Tag))
}

func NormalizeRouteTag(tag string) string {
	if tag == "" {
		return DefaultRouteTag
	}
	return tag
}

func WireRouteTag(tag string) string {
	if NormalizeRouteTag(tag) == DefaultRouteTag {
		return ""
	}
	return tag
}

// Source is a pair of a router-id and a prefix (Babel Section 2.7).
type Source struct {
	NodeId
	netip.Prefix
	Tag string
}

func (s Source) Key() RouteKey {
	return NewRouteKey(s.Prefix, s.Tag)
}

func (s Source) Normalize() Source {
	s.Tag = WireRouteTag(s.Tag)
	return s
}

func (s Source) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("router", string(s.NodeId)),
		slog.String("prefix", s.Prefix.String()),
		slog.String("tag", NormalizeRouteTag(s.Tag)),
	)
}

func (s Source) String() string {
	return fmt.Sprintf("(router: %s, prefix: %s, tag: %s)", s.NodeId, s.Prefix, NormalizeRouteTag(s.Tag))
}

type Advertisement struct {
	NodeId
	Expiry        time.Time
	IsPassiveHold bool
	MetricFn      func() uint32
	ExpiryFn      func()
}
type RouterState struct {
	*RouterTunables
	Id         NodeId
	SelfSeqno  map[RouteKey]uint16
	Routes     map[RouteKey]SelRoute
	Sources    map[Source]FD
	Neighbours []*Neighbour
	// Advertised is a map tracking the prefix and the time it will be advertised until
	Advertised map[RouteKey]Advertisement
}

func (s *RouterState) GetSeqno(key RouteKey) uint16 {
	seq, ok := s.SelfSeqno[key]
	if !ok {
		return 0
	}
	return seq
}

func (s *RouterState) SetSeqno(key RouteKey, seqno uint16) {
	s.SelfSeqno[key] = seqno
}

func (s *RouterState) StringRoutes() string {
	buf := make([]string, 0)
	for key, route := range s.Routes {
		buf = append(buf, fmt.Sprintf("%s via %s", key, route))
	}
	slices.Sort(buf)
	return strings.Join(buf, "\n")
}

type Neighbour struct {
	Id     NodeId
	Routes map[RouteKey]NeighRoute
	Eps    []Endpoint
}

type FD struct {
	Seqno  uint16
	Metric uint32
}

func (fd FD) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Uint64("seqno", uint64(fd.Seqno)),
		slog.Uint64("metric", uint64(fd.Metric)),
	)
}

type PubRoute struct {
	Source
	// FD will depend on which table the route is in. In the neighbour table,
	// it represents the metric advertised by the neighbour.
	// In the selected route table, it represents the metric that
	// the route will be advertised with.
	FD
}

func (r PubRoute) String() string {
	if NormalizeRouteTag(r.Tag) == DefaultRouteTag {
		return fmt.Sprintf("(router: %s, prefix: %s, seqno: %d, metric: %d)", r.NodeId, r.Prefix, r.Seqno, r.Metric)
	}
	return fmt.Sprintf("(router: %s, prefix: %s, tag: %s, seqno: %d, metric: %d)", r.NodeId, r.Prefix, NormalizeRouteTag(r.Tag), r.Seqno, r.Metric)
}

func (r PubRoute) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("router", string(r.NodeId)),
		slog.String("prefix", r.Prefix.String()),
		slog.String("tag", NormalizeRouteTag(r.Tag)),
		slog.Uint64("seqno", uint64(r.Seqno)),
		slog.Uint64("metric", uint64(r.Metric)),
	)
}

type NeighRoute struct {
	PubRoute
	ExpireAt time.Time // when the route expires
}

type SelRoute struct {
	PubRoute
	Nh          NodeId    // next hop node
	ExpireAt    time.Time // when the route expires
	RetractedBy []NodeId
}

func (r SelRoute) String() string {
	if NormalizeRouteTag(r.Tag) == DefaultRouteTag {
		return fmt.Sprintf("(nh: %s, router: %s, prefix: %s, seqno: %d, metric: %d)", r.Nh, r.NodeId, r.Prefix, r.Seqno, r.Metric)
	}
	return fmt.Sprintf("(nh: %s, router: %s, prefix: %s, tag: %s, seqno: %d, metric: %d)", r.Nh, r.NodeId, r.Prefix, NormalizeRouteTag(r.Tag), r.Seqno, r.Metric)
}

func (r SelRoute) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Any("nh", r.Nh), // Use Any if Nh is an object/interface
		slog.String("router", string(r.NodeId)),
		slog.String("prefix", r.Prefix.String()),
		slog.String("tag", NormalizeRouteTag(r.Tag)),
		slog.Uint64("seqno", uint64(r.Seqno)),
		slog.Uint64("metric", uint64(r.Metric)),
	)
}

func (s *RouterState) GetNeighbour(node NodeId) *Neighbour {
	nIdx := slices.IndexFunc(s.Neighbours, func(neighbour *Neighbour) bool {
		return neighbour.Id == node
	})
	if nIdx == -1 {
		return nil
	}
	return s.Neighbours[nIdx]
}
