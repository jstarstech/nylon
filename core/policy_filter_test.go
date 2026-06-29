package core

import (
	"net/netip"
	"testing"

	"github.com/encodeous/nylon/polyamide/device"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// mkPacket builds a minimal TCElement carrying an IP header of the given version
// with the given src/dst, enough for the access-policy filter to read them.
func mkPacket(ver int, src, dst netip.Addr) *device.TCElement {
	size := 4
	switch ver {
	case 4:
		size = ipv4.HeaderLen
	case 6:
		size = ipv6.HeaderLen
	}
	elem := &device.TCElement{Packet: make([]byte, size)}
	elem.SetIPVersion(ver)
	if ver == 4 || ver == 6 {
		elem.SetSrc(src)
		elem.SetDst(dst)
	}
	return elem
}

// The data-plane filter drops denied (src,dst) and passes everything else.
// policyApplyCfg: cust 10.0.0.50 may reach only the internet; node-1 10.0.0.1
// is ungoverned (allow-all).
func TestEnforceAccessPolicy_DataPlane(t *testing.T) {
	n := policyTestNylon()
	n.storeAccessPolicy(policyApplyCfg())

	cust := pAddr("10.0.0.50")
	infra := pAddr("10.0.0.1")
	pub := pAddr("8.8.8.8")

	cases := []struct {
		name string
		pkt  *device.TCElement
		want device.TCAction
	}{
		{"governed customer -> mesh infra: DROP", mkPacket(4, cust, infra), device.TcDrop},
		{"governed customer -> internet: PASS", mkPacket(4, cust, pub), device.TcPass},
		{"ungoverned infra -> customer: PASS", mkPacket(4, infra, cust), device.TcPass},
		{"non-IP packet: PASS", mkPacket(0, netip.Addr{}, netip.Addr{}), device.TcPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			act, err := n.enforceAccessPolicy(nil, c.pkt)
			assert.NoError(t, err)
			assert.Equal(t, c.want, act)
		})
	}
}

// PolicyDrops counts only dropped packets, once each.
func TestEnforceAccessPolicy_DropCounter(t *testing.T) {
	n := policyTestNylon()
	n.storeAccessPolicy(policyApplyCfg())

	drop := mkPacket(4, pAddr("10.0.0.50"), pAddr("10.0.0.1"))
	pass := mkPacket(4, pAddr("10.0.0.50"), pAddr("8.8.8.8"))

	for i := 0; i < 3; i++ {
		if _, err := n.enforceAccessPolicy(nil, drop); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := n.enforceAccessPolicy(nil, pass); err != nil { // allowed, must not count
		t.Fatal(err)
	}

	assert.Equal(t, uint64(3), n.router.PolicyDrops.Load())
}
