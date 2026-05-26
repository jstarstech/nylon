package core

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/device"
	"github.com/encodeous/nylon/protocol"
	"github.com/encodeous/nylon/state"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"google.golang.org/protobuf/proto"
)

func checksum(data []byte) uint16 {
	var csum uint32
	for i := 0; i < len(data)-1; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		csum += uint32(data[len(data)-1]) << 8
	}
	csum = (csum >> 16) + (csum & 0xffff)
	csum = (csum >> 16) + (csum & 0xffff)
	return ^uint16(csum)
}

func icmpv6Checksum(msg []byte, src, dst netip.Addr) uint16 {
	var csum uint32
	src16 := src.As16()
	dst16 := dst.As16()
	for i := 0; i < 16; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(src16[i : i+2]))
	}
	for i := 0; i < 16; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(dst16[i : i+2]))
	}
	csum += uint32(len(msg))
	csum += 58
	for i := 0; i < len(msg)-1; i += 2 {
		csum += uint32(binary.BigEndian.Uint16(msg[i : i+2]))
	}
	if len(msg)%2 == 1 {
		csum += uint32(msg[len(msg)-1]) << 8
	}
	csum = (csum >> 16) + (csum & 0xffff)
	csum = (csum >> 16) + (csum & 0xffff)
	return ^uint16(csum)
}

const (
	NyProtoId = 8
)

// polyamide traffic control for nylon

func (n *Nylon) InstallTC() {
	t := n.Trace

	if n.DBG_trace_tc {
		n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
			if packet.Validate() { // make sure it's an IP packet
				peer := packet.FromPeer
				if peer == nil {
					peer = packet.ToPeer
				}
				src := packet.GetSrc()
				dst := packet.GetDst()
				if src.IsValid() &&
					dst.IsValid() &&
					peer != nil &&
					src != netip.IPv4Unspecified() && src != netip.IPv6Unspecified() &&
					dst != netip.IPv4Unspecified() && dst != netip.IPv6Unspecified() {
					t.Submit(fmt.Sprintf("Unhandled TC packet: %v -> %v, peer %s\n", packet.GetSrc(), packet.GetDst(), peer))
				}
			}
			return device.TcPass, nil
		})
	}

	// policy route filter: match incoming packets from passive clients against routing policies
	n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
		if !packet.Incoming() || !packet.Validate() {
			return device.TcPass, nil
		}
		src := packet.GetSrc()
		dst := packet.GetDst()
		if !src.IsValid() || !dst.IsValid() {
			return device.TcPass, nil
		}
		pr := n.PolicyRoutes.Load()
		if pr == nil {
			return device.TcPass, nil
		}
		for _, pol := range *pr {
			if pol.Src.Contains(src) && pol.Dst.Contains(dst) {
				packet.ToPeer = pol.Peer
				if n.DBG_trace_tc {
					t.Submit(fmt.Sprintf("PolicyFwd: %v -> %v via policy route\n", src, dst))
				}
				return device.TcForward, nil
			}
		}
		return device.TcPass, nil
	})

	// bounce back packets if using system routing
	if n.UseSystemRouting {
		n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
			if packet.Incoming() {
				// bounce incoming packets
				//dev.Log.Verbosef("BounceFwd packet: %v -> %v", packet.GetSrc(), packet.GetDst())
				return device.TcBounce, nil
			}
			return device.TcPass, nil
		})
		// forward only outgoing packets based on the routing table
		n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
			entry, ok := n.router.ForwardTable.Load().Lookup(packet.GetDst())
			if ok && !packet.Incoming() {
				if entry.Blackhole {
					return device.TcDrop, nil
				}
				packet.ToPeer = entry.Peer
				if n.DBG_trace_tc {
					t.Submit(fmt.Sprintf("Fwd packet: %v -> %v, via %s\n", packet.GetSrc(), packet.GetDst(), entry.Nh))
				}
				return device.TcForward, nil
			}
			return device.TcPass, nil
		})
	} else {
		// forward packets based on the routing table
		n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
			entry, ok := n.router.ForwardTable.Load().Lookup(packet.GetDst())
			if ok {
				if entry.Blackhole {
					return device.TcDrop, nil
				}
				packet.ToPeer = entry.Peer
				if n.DBG_trace_tc {
					t.Submit(fmt.Sprintf("Fwd packet: %v -> %v, via %s\n", packet.GetSrc(), packet.GetDst(), entry.Nh))
				}
				return device.TcForward, nil
			}
			return device.TcPass, nil
		})
	}

	// override policy route filter: runs before ForwardTable, after TTL
	n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
		if !packet.Incoming() || !packet.Validate() {
			return device.TcPass, nil
		}
		src := packet.GetSrc()
		dst := packet.GetDst()
		if !src.IsValid() || !dst.IsValid() {
			return device.TcPass, nil
		}
		pr := n.OverridePolicyRoutes.Load()
		if pr == nil {
			return device.TcPass, nil
		}
		for _, pol := range *pr {
			if pol.Src.Contains(src) && pol.Dst.Contains(dst) {
				packet.ToPeer = pol.Peer
				if n.DBG_trace_tc {
					t.Submit(fmt.Sprintf("PolicyFwd(override): %v -> %v\n", src, dst))
				}
				return device.TcForward, nil
			}
		}
		return device.TcPass, nil
	})

	// handle passive client traffic separately

	// bounce back packets destined for the current node
	n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
		entry, ok := n.router.ExitTable.Load().Lookup(packet.GetDst())
		// we should only accept packets destined to us, but not our passive clients
		if ok && entry.Nh == n.LocalCfg.Id {
			if n.DBG_trace_tc {
				t.Submit(fmt.Sprintf("Exit: %v -> %v\n", packet.GetSrc(), packet.GetDst()))
			}
			//dev.Log.Verbosef("BounceCur packet: %v -> %v", packet.GetSrc(), packet.GetDst())
			return device.TcBounce, nil
		}
		//dev.Log.Verbosef("pass packet: %v -> %v, %v", packet.GetSrc(), packet.GetDst(), entry.Nh)
		return device.TcPass, nil
	})

	// handle incoming nylon packets
	n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
		if packet.Incoming() && packet.GetIPVersion() == NyProtoId {
			n.handleNylonPacket(packet.Payload(), packet.FromEp, packet.FromPeer)
			return device.TcDrop, nil
		}
		return device.TcPass, nil
	})

	// TTL handler: installed last so it runs FIRST (slices.Backward)
	// Must always be the last installed filter.
	n.Device.InstallFilter(func(dev *device.Device, packet *device.TCElement) (device.TCAction, error) {
		if n.LocalCfg.DisableTTL {
			return device.TcPass, nil
		}
		if !packet.Incoming() || !packet.Validate() {
			return device.TcPass, nil
		}
		ver := packet.GetIPVersion()
		if ver != 4 && ver != 6 {
			return device.TcPass, nil
		}
		ttl := packet.GetTTL()
		if ttl >= 1 {
			ttl--
			packet.DecrementTTL()
		}
		if ttl == 0 && packet.FromPeer != nil {
			n.Log.Debug("icmp ttl exceeded", "src", packet.GetSrc(), "dst", packet.GetDst())
			if n.DBG_trace_tc {
				t.Submit(fmt.Sprintf("TTL Expired: %v -> %v\n", packet.GetSrc(), packet.GetDst()))
			}

			var localSrc netip.Addr
			for _, addr := range n.GetRouter(n.LocalCfg.Id).Addresses {
				if ver == 4 && addr.Is4() {
					localSrc = addr
					break
				}
				if ver == 6 && addr.Is6() {
					localSrc = addr
					break
				}
			}
			if !localSrc.IsValid() {
				return device.TcDrop, nil
			}

			origSrc := packet.GetSrc()
			origPayload := packet.Payload()

			if ver == 4 {
				icmpBodyLen := ipv4.HeaderLen + 8
				if len(origPayload) < 8 {
					icmpBodyLen = ipv4.HeaderLen + len(origPayload)
				}
				newTotalLen := ipv4.HeaderLen + 8 + icmpBodyLen
				packet.Packet = packet.Packet[:newTotalLen]

				icmpHdrOff := ipv4.HeaderLen
				icmpBodyOff := icmpHdrOff + 8
				copy(packet.Packet[icmpBodyOff:], packet.Packet[:ipv4.HeaderLen])
				copy(packet.Packet[icmpBodyOff+ipv4.HeaderLen:], origPayload[:icmpBodyLen-ipv4.HeaderLen])

				icmpHdr := packet.Packet[icmpHdrOff : icmpHdrOff+8]
				icmpHdr[0] = 11
				icmpHdr[1] = 0
				binary.BigEndian.PutUint16(icmpHdr[2:4], 0)
				binary.BigEndian.PutUint32(icmpHdr[4:8], 0)
				csum := checksum(packet.Packet[icmpHdrOff : icmpHdrOff+8+icmpBodyLen])
				binary.BigEndian.PutUint16(icmpHdr[2:4], csum)

				packet.SetSrc(localSrc)
				packet.SetDst(origSrc)
				packet.Packet[8] = 64
				packet.Packet[9] = 1
				binary.BigEndian.PutUint16(packet.Packet[2:4], uint16(newTotalLen))
				binary.BigEndian.PutUint16(packet.Packet[10:12], 0)
				binary.BigEndian.PutUint16(packet.Packet[10:12], checksum(packet.Packet[:ipv4.HeaderLen]))
				packet.SetLength(uint16(newTotalLen))
			} else {
				icmpBodyLen := ipv6.HeaderLen + 8
				if len(origPayload) < 8 {
					icmpBodyLen = ipv6.HeaderLen + len(origPayload)
				}
				newTotalLen := ipv6.HeaderLen + 8 + icmpBodyLen
				packet.Packet = packet.Packet[:newTotalLen]

				icmpHdrOff := ipv6.HeaderLen
				icmpBodyOff := icmpHdrOff + 8
				copy(packet.Packet[icmpBodyOff:], packet.Packet[:ipv6.HeaderLen])
				copy(packet.Packet[icmpBodyOff+ipv6.HeaderLen:], origPayload[:icmpBodyLen-ipv6.HeaderLen])

				icmpHdr := packet.Packet[icmpHdrOff : icmpHdrOff+8]
				icmpHdr[0] = 3
				icmpHdr[1] = 0
				binary.BigEndian.PutUint16(icmpHdr[2:4], 0)
				binary.BigEndian.PutUint32(icmpHdr[4:8], 0)

				icmpMsg := packet.Packet[icmpHdrOff : icmpHdrOff+8+icmpBodyLen]
				csum := icmpv6Checksum(icmpMsg, localSrc, origSrc)
				binary.BigEndian.PutUint16(icmpHdr[2:4], csum)

				packet.SetSrc(localSrc)
				packet.SetDst(origSrc)
				packet.Packet[7] = 255
				packet.Packet[6] = 58
				binary.BigEndian.PutUint16(packet.Packet[4:6], uint16(8+icmpBodyLen))
				packet.SetLength(uint16(newTotalLen))
			}

			packet.ToPeer = packet.FromPeer
			return device.TcForward, nil
		}
		return device.TcPass, nil
	})
}

func (n *Nylon) SendNylon(pkt *protocol.Ny, endpoint conn.Endpoint, peer *device.Peer) error {
	return n.SendNylonBundle(&protocol.TransportBundle{Packets: []*protocol.Ny{pkt}}, endpoint, peer)
}

func (n *Nylon) SendNylonBundle(pkt *protocol.TransportBundle, endpoint conn.Endpoint, peer *device.Peer) error {
	tce := n.Device.NewTCElement()
	offset := device.MessageTransportOffsetContent + device.PolyHeaderSize
	buf, err := proto.MarshalOptions{
		Deterministic: true,
	}.MarshalAppend(tce.Buffer[offset:offset], pkt)
	if err != nil {
		n.Device.PutMessageBuffer(tce.Buffer)
		n.Device.PutTCElement(tce)
		return err
	}
	tce.InitPacket(NyProtoId, uint16(len(buf)+device.PolyHeaderSize))
	tce.Priority = device.TcHighPriority

	tce.ToEp = endpoint
	tce.ToPeer = peer

	// TODO: Optimize? is it worth it?

	tcs := device.NewTCState()

	n.Device.TCBatch([]*device.TCElement{tce}, tcs)
	return nil
}

func (n *Nylon) handleNylonPacket(packet []byte, endpoint conn.Endpoint, peer *device.Peer) {
	// we need to be careful here, since this function is called on the dataplane
	bundle := &protocol.TransportBundle{}
	err := proto.Unmarshal(packet, bundle)
	if err != nil {
		// log skipped message
		n.Log.Debug("Failed to unmarshal packet", "err", err)
		return
	}

	nt := n.PeerMap.Load()
	if nt == nil {
		return // not loaded yet
	}
	neigh, ok := (*nt)[state.NyPublicKey(peer.GetPublicKey())]
	if !ok {
		// this should not be possible
		panic("impossible state, peer added, but not a node in the network")
	}

	defer func() {
		err := recover()
		if err != nil {
			n.Log.Error("panic while handling poly socket", "err", err)
		}
	}()

	for _, pkt := range bundle.Packets {
		switch pkt.Type.(type) {
		case *protocol.Ny_SeqnoRequestOp:
			n.Dispatch(func() error {
				return n.routerHandleSeqnoRequest(neigh, pkt.GetSeqnoRequestOp())
			})
		case *protocol.Ny_RouteOp:
			n.Dispatch(func() error {
				return n.routerHandleRouteUpdate(neigh, pkt.GetRouteOp())
			})
		case *protocol.Ny_AckRetractOp:
			n.Dispatch(func() error {
				return n.routerHandleAckRetract(neigh, pkt.GetAckRetractOp())
			})
		case *protocol.Ny_ProbeOp:
			// we don't want to wait for dispatch before responding to this packet
			handleProbe(n, pkt.GetProbeOp(), endpoint, peer, neigh)
		}
	}
}
