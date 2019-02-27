package netcore

import (
	"container/list"
	"errors"
	"io"
	"net"
	"time"

	"github.com/Evan2698/chimney/utils"
	"github.com/Evan2698/netstackm/ipv4"
	"github.com/Evan2698/netstackm/udp"
)

// UDPConnection ...
type UDPConnection struct {
	Src, Dst                    net.IP
	SourcePort, DestinationPort uint16
	Stack                       *Stack
	cache                       *list.List
	Recv                        chan []byte
	current                     *State
	closed                      bool
}

// LocalAddr returns the local network address.
func (c *UDPConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.Src,
		Port: int(c.SourcePort),
		Zone: "",
	}
}

// RemoteAddr returns the remote network address.
func (c *UDPConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.Dst,
		Port: int(c.DestinationPort),
		Zone: "",
	}
}

// Read return n indicate byte numbers.
func (c *UDPConnection) Read(b []byte) (n int, err error) {
	if c.closed {
		return 0, errors.New("UDP Closed")
	}

	n = -1
	state := c.current
	state.lockObject.Lock()
	if c.cache.Len() > 0 {
		v, ok := c.cache.Front().Value.([]byte)
		if ok {
			n = copy(b, v)
		}
		c.cache.Remove(c.cache.Front())
	}
	state.lockObject.Unlock()
	if n > -1 {
		return n, nil
	}

	select {
	case <-time.After(300 * time.Second):
		utils.LOG.Println("Timeout occured")
		return 0, errors.New("Timeout occured")
	case _, ok := <-c.Recv:
		if !ok {
			// connection closed?
			if c.cache.Len() == 0 {
				return 0, io.EOF
			}
		}
		state.lockObject.Lock()
		if c.cache.Len() > 0 {
			v, ok := c.cache.Front().Value.([]byte)
			if ok {
				n = copy(b, v)
			}
			c.cache.Remove(c.cache.Front())
		}
		state.lockObject.Unlock()
		return n, nil
	}
}

// Write writes data to the connection.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (c *UDPConnection) Write(b []byte) (n int, err error) {
	if c.closed {
		return 0, errors.New("UDP Closed")
	}

	if len(b) > 0 {
		tmpu := udp.NewUDP()
		tmpu.SrcIP = c.Dst
		tmpu.DstIP = c.Src
		tmpu.DstPort = c.SourcePort
		tmpu.SrcPort = c.DestinationPort
		tmpu.Payload = b
		l := c.buildIPPacket(tmpu)
		for _, item := range l {
			c.Stack.SendTo(item.ToBytes())
		}
	}

	return len(b), nil
}

func (c *UDPConnection) buildIPPacket(pkt *udp.UDP) []*ipv4.IPv4 {
	var lu []*ipv4.IPv4

	threshhold := ipv4.MTU - 28

	rest := pkt.ToBytes()

	n := len(rest)
	sz := n

	var ippkt *ipv4.IPv4

	var offset uint16

	for n > 0 {

		ippkt = ipv4.NewIPv4()
		ippkt.Version = 4
		ippkt.SrcIP = pkt.SrcIP
		ippkt.DstIP = pkt.DstIP
		ippkt.Protocol = ipv4.IPProtocolUDP
		ippkt.TTL = 128
		ippkt.FragmentOffset = offset
		ippkt.Identification = ipv4.GeneratorIPID()
		ippkt.Flags = 0x2
		if sz > threshhold {
			ippkt.Flags = 0x1
		}

		if n > threshhold {
			ippkt.PayLoad = rest[:threshhold]
			rest = rest[threshhold:]
			offset += uint16(threshhold / 8)

		} else {
			ippkt.PayLoad = rest[:]
			rest = nil
			ippkt.Flags = 0x2
		}
		n = len(rest)
		if len(lu) > 0 {
			ippkt.Identification = lu[0].Identification
		}
		lu = append(lu, ippkt)
	}

	return lu
}

// Open ..
func (c *UDPConnection) Open(t *udp.UDP) error {

	state := &State{
		SrcPort:  t.SrcPort,
		DestPort: t.DstPort,
		SrcIP:    t.SrcIP,
		DestIP:   t.DstIP,
		Connu:    c,
	}

	err := c.Stack.u.Add(t.SrcIP, t.DstIP, t.SrcPort, t.DstPort, state)
	if err != nil {
		utils.LOG.Println("can not create state ", err)
		return err
	}
	state.lockObject.Lock()
	c.current = state
	state.lockObject.Unlock()
	c.Stack.b <- c
	c.dispatch(t)
	return nil
}

func (c *UDPConnection) run(t *udp.UDP) {
	if t.IsStop() {
		utils.LOG.Print("udp loop exit!!")
		return
	}

	pl := len(t.Payload)
	state := c.current
	if pl > 0 {
		state.lockObject.Lock()
		c.cache.PushBack(t.Payload)
		state.lockObject.Unlock()
		select {
		case state.Connu.Recv <- []byte{}:
		default:
		}
	}

}

func (c *UDPConnection) dispatch(t *udp.UDP) {
	c.run(t)
}

func (c *UDPConnection) handleClose() {
	c.closed = true
	c.Stack.u.Remove(c.Src, c.Dst, c.SourcePort, c.DestinationPort)
}

// Close ...
func (c *UDPConnection) Close() {
	c.handleClose()
	u := udp.NewUDP()
	u.Stop = true
	close(c.Recv)
}

// NewUDPConnection ..
func NewUDPConnection(src, dst net.IP, sport, dport uint16, s *Stack) *UDPConnection {

	v := &UDPConnection{
		Src:             src,
		Dst:             dst,
		SourcePort:      sport,
		DestinationPort: dport,
		Stack:           s,
		Recv:            make(chan []byte),
		cache:           list.New(),
	}
	return v
}
