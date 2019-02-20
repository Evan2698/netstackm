package netcore

import (
	"errors"
	"math/rand"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/Evan2698/netstackm/tun"
	"github.com/Evan2698/netstackm/udp"

	"github.com/Evan2698/netstackm/tcp"

	"github.com/Evan2698/chimney/utils"
	"github.com/Evan2698/netstackm/ipv4"
)

// Stack ...
type Stack struct {
	tun tun.ReadWriteCloseStoper

	r *rand.Rand

	m sync.Mutex

	sendQueue [][]byte
	buffer    []byte

	t *StateTable
	u *StateTable

	a chan *Connection
	b chan *UDPConnection

	stop bool
	exit chan bool
}

// New ...
func New(fd int) (*Stack, error) {

	err := syscall.SetNonblock(fd, true)
	if err != nil {
		utils.LOG.Println("set socket option non-block failed", err)
		return nil, err
	}

	f := os.NewFile((uintptr)(fd), "")

	v := &Stack{
		tun: tun.NewTunDevice(f),
		r:   rand.New(rand.NewSource(time.Now().UTC().UnixNano())),
		t: &StateTable{
			table: make(map[string]*State),
		},
		a: make(chan *Connection, 20),
		u: &StateTable{
			table: make(map[string]*State),
		},
		b:    make(chan *UDPConnection, 20),
		exit: make(chan bool),
	}

	return v, nil
}

// DefaultBufferSize ...
var DefaultBufferSize int = ipv4.MTU

// Start ...
func (s *Stack) Start() {
	go func() {

		defer func() {
			s.exit <- true
		}()

		for {
			if s.stop {
				utils.LOG.Println("stack exit!!!^^^^^^")
				break
			}
			var buffer = make([]byte, DefaultBufferSize)
			n, err := s.tun.Read(buffer)
			if err != nil {
				utils.LOG.Println("read from tun failed:", err)
				break
			}

			utils.LOG.Println(n, "read bytes from tun!!")

			if n < 20 {
				utils.LOG.Println("ip format is incorrect", n, "bytes")
				continue
			}

			ip := ipv4.NewIPv4()
			err = ip.TryParseBasicHeader(buffer[:20])
			if err != nil {
				utils.LOG.Println("parse ip base header failed", err)
				continue
			}

			if ip.IsStop() {
				utils.LOG.Println("IP package stop flag, stack will exit!!! ")
				break
			}

			err = ip.TryParseBody(buffer[20:n])
			if err != nil {
				utils.LOG.Println("pase ip body failed", err)
				continue
			}

			if ip.Flags&0x1 != 0 || ip.FragmentOffset != 0 {
				utils.LOG.Print("partial packet received")
				end := ipv4.Merge(ip)
				if end {
					ip = ipv4.GetHugPkg(ip.Identification)
					utils.LOG.Print("partial packets were merged. ", ip.Identification)
					ip.Dump()

				} else {
					continue
				}
			}

			switch ip.Protocol {
			case ipv4.IPProtocolTCP:
				s.handleTCP(ip)
			case ipv4.IPProtocolUDP:
				s.handleUDP(ip)
			default:
				ip.Dump()
			}

		}

	}()
}

func (s *Stack) handleTCP(ip *ipv4.IPv4) {
	pkt, err := tcp.ParseTCP(ip)
	if err != nil {
		utils.LOG.Println("pase TCP failed", err)
		return
	}

	state := s.t.Get(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort)
	if state == nil {
		if pkt.RST {
			utils.LOG.Println("no connect, so does not handle RST message")
			pkt.Dump()
			return
		}

		if !pkt.SYN {
			relay := rst(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, pkt.Sequence, pkt.Acknowledgment, uint32(len(pkt.Payload)))
			s.sendtolow(packtcp(relay), false)
			return
		}

		con := NewConnection(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, s)
		err = con.Open(pkt)
		if err != nil {
			utils.LOG.Println("create connection failed")
			pkt.Dump()
			return
		}

	} else {
		state.Conn.dispatch(pkt)
	}
}

func (s *Stack) handleUDP(ip *ipv4.IPv4) {
	pkt, err := udp.TryParse(ip)
	if err != nil {
		utils.LOG.Println("pase UDP failed", err)
		return
	}

	state := s.u.Get(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort)
	if state == nil {
		con := NewUDPConnection(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, s)
		err = con.Open(pkt)
		if err != nil {
			utils.LOG.Println("create connection failed")
			pkt.Dump()
			return
		}

	} else {
		state.Connu.dispatch(pkt)
	}

}

// Accept ..
func (s *Stack) Accept() (*Connection, error) {
	if s.stop {
		return nil, errors.New("closed")
	}

	c, ok := <-s.a
	if !ok {
		return nil, errors.New("channel closed")
	}

	return c, nil
}

// AcceptUDP ..
func (s *Stack) AcceptUDP() (*UDPConnection, error) {
	if s.stop {
		return nil, errors.New("closed")
	}

	c, ok := <-s.b
	if !ok {
		return nil, errors.New("channel closed")
	}

	return c, nil
}

func (s *Stack) sendtolow(b []byte, sync bool) {
	if !sync {
		go func() {
			_, err := s.tun.Write(b)
			if err != nil {
				utils.LOG.Println("write to tun failed", err)
			}
		}()

	} else {
		_, err := s.tun.Write(b)
		if err != nil {
			utils.LOG.Println("write to tun failed", err)
		}
	}
}

// Close ...
func (s *Stack) Close() {
	o, err := net.Dial("tcp", "11.11.11.11:11111")
	if err == nil {
		o.Close()
	}

	s.stop = true
	s.tun.SetStop(true)
	<-s.exit
	close(s.exit)
	time.Sleep(time.Second * 2)
	if s.a != nil {
		close(s.a)
		s.a = nil
	}

	if s.b != nil {
		close(s.b)
		s.b = nil
	}

	if s.t != nil {
		s.t.ClearAll()
	}

	if s.u != nil {
		s.u.ClearAll()
	}

	if s.tun != nil {
		s.tun.Close()
		s.tun = nil
	}
	s.t = nil
	s.u = nil
	s.buffer = nil
	s.sendQueue = nil
}
