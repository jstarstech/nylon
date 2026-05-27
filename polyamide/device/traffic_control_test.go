package device

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"testing"

	"github.com/encodeous/nylon/polyamide/conn"
	"github.com/encodeous/nylon/polyamide/tun"
	"github.com/encodeous/nylon/polyamide/tun/tuntest"
)

type testTun struct {
	lastOffset int
	lastPacket []byte
}

func (t *testTun) File() *os.File { return nil }

func (t *testTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	return 0, io.EOF
}

func (t *testTun) Write(bufs [][]byte, offset int) (int, error) {
	t.lastOffset = offset
	if len(bufs) > 0 {
		t.lastPacket = append(t.lastPacket[:0], bufs[0][offset:]...)
	}
	return len(bufs), nil
}

func (t *testTun) MTU() (int, error) { return DefaultMTU, nil }

func (t *testTun) Name() (string, error) { return "testTun0", nil }

func (t *testTun) Events() <-chan tun.Event { return nil }

func (t *testTun) Close() error { return nil }

func (t *testTun) BatchSize() int { return 1 }

type testBind struct{}

var _ conn.Bind = (*testBind)(nil)

func (b *testBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return nil, port, nil
}

func (b *testBind) Close() error { return nil }

func (b *testBind) BatchSize() int { return 1 }

func (b *testBind) SetMark(mark uint32) error { return nil }

func (b *testBind) Send(bufs [][]byte, ep conn.Endpoint) error { return nil }

func (b *testBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return nil, errors.New("not implemented")
}

func TestTCBounceUsesVirtioHeaderOffset(t *testing.T) {
	fakeTun := &testTun{}
	dev := &Device{
		Log: &Logger{Verbosef: DiscardLogf, Errorf: DiscardLogf},
	}
	dev.tun.device = fakeTun
	dev.net.bind = &testBind{}
	dev.PopulatePools()
	dev.TCFilters = []TCFilter{
		func(dev *Device, packet *TCElement) (TCAction, error) {
			return TcBounce, nil
		},
	}

	elem := dev.NewTCElement()
	defer dev.PutTCElement(elem)
	elem.Buffer = dev.GetMessageBuffer()
	defer dev.PutMessageBuffer(elem.Buffer)

	src := netip.AddrFrom4([4]byte{10, 0, 0, 1})
	dst := netip.AddrFrom4([4]byte{10, 0, 0, 2})
	packet := tuntest.Ping(dst, src)
	copy(elem.Buffer[MessageTransportHeaderSize:], packet)
	elem.Packet = elem.Buffer[MessageTransportHeaderSize : MessageTransportHeaderSize+len(packet)]

	tcs := NewTCState()
	dev.TCBatch([]*TCElement{elem}, tcs)

	if fakeTun.lastOffset != tun.VirtioNetHdrLen {
		t.Fatalf("bounce write offset = %d, want %d", fakeTun.lastOffset, tun.VirtioNetHdrLen)
	}
	if string(fakeTun.lastPacket) != string(packet) {
		t.Fatalf("bounced packet mismatch")
	}
}
