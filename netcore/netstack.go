package netcore

import (
	"errors"
	"fmt"
	"math/rand"
	"sync"
	"syscall"
	"time"

	"github.com/Evan2698/netstackm/common"

	"github.com/Evan2698/netstackm/udp"

	"github.com/Evan2698/netstackm/tcp"

	"github.com/Evan2698/chimney/utils"
	"github.com/Evan2698/netstackm/ipv4"
)

// Stack ...
type Stack struct {
	r *rand.Rand

	m sync.Mutex

	sendQueue [][]byte
	buffer    []byte

	t *StateTable
	u *StateTable

	a    chan *Connection
	b    chan *UDPConnection
	epfd int
	stop bool
	tun  int
}

// New ...
func New(fd int) (*Stack, error) {

	err := syscall.SetNonblock(fd, true)
	if err != nil {
		utils.LOG.Println("set socket option non-block failed", err)
		return nil, err
	}

	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1)
	if err != nil {
		utils.LOG.Println("set socket syscall.IPPROTO_IP failed", err)
		return nil, err
	}

	ep, err := syscall.EpollCreate1(0)
	if err != nil {
		utils.LOG.Println("epoll_create1:", err.Error())
		return nil, err
	}

	err = syscall.EpollCtl(ep, syscall.EPOLL_CTL_ADD, fd, &syscall.EpollEvent{
		Events: syscall.EPOLLIN | syscall.EPOLLERR, /*| syscall.EPOLL_NONBLOCK  | syscall.EPOLLOUT | syscall.EPOLLET*/
		Fd:     int32(fd),
	})
	if err != nil {
		utils.LOG.Println("epollctl:", err.Error())
		syscall.Close(ep)
		return nil, err
	}

	v := &Stack{
		epfd: ep,
		r:    rand.New(rand.NewSource(time.Now().UTC().UnixNano())),
		t: &StateTable{
			table: make(map[string]*State),
		},
		a: make(chan *Connection, 20),
		u: &StateTable{
			table: make(map[string]*State),
		},
		b:   make(chan *UDPConnection, 20),
		tun: fd,
	}

	return v, nil
}

// DefaultBufferSize ...
var DefaultBufferSize int = ipv4.MTU

const (
	MaxEpollEvents = 64
)

// Start ...
func (s *Stack) Start() {
	go func() {
		var events [MaxEpollEvents]syscall.EpollEvent

		for {
			nevents, err := syscall.EpollWait(s.epfd, events[:], -1)
			if err != nil {
				utils.LOG.Println("epoll_wait: ", err, "exit stack!!!!")
				break
			}

			for ev := 0; ev < nevents; ev++ {
				if events[ev].Events&syscall.EPOLLERR == syscall.EPOLLERR {
					s.handleEventPollErr(events[ev])
				}

				if events[ev].Events&syscall.EPOLLIN == syscall.EPOLLIN {
					s.handleEventPollIn(events[ev])
				}
			}
		}

	}()
}

func (s *Stack) handleEventPollIn(event syscall.EpollEvent) {

	buffer := make([]byte, common.CONFIGMTU)

	n, _, err := syscall.Recvfrom(int(event.Fd), buffer, 0)
	if err != nil {
		utils.LOG.Println("Could not receive from descriptor: %s", err.Error())
		return
	}
	if n < 20 {
		utils.LOG.Println("it is not a ip packet!!!", n)
		return
	}

	value := buffer[:n]

	ip := ipv4.NewIPv4()
	err = ip.TryParseBasicHeader(value[:20])
	if err != nil {
		utils.LOG.Println("can not parse ip header", err)
		return
	}

	err = ip.TryParseBody(value[20:])
	if err != nil {
		utils.LOG.Println("failed to parse ip ", err)
		return
	}

	if ip.IHL < 5 {
		utils.LOG.Println("IP header length is invalid.")
	} else {
		switch ip.Protocol {
		case ipv4.IPProtocolTCP /* tcp */ :
			s.handleTCP(ip)
		case ipv4.IPProtocolUDP /* udp */ :
			s.handleUDP(ip)
		default:
			utils.LOG.Println("unhandled protocol: ", ip.Protocol.String())
		}
	}
}

func (s *Stack) handleEventPollErr(event syscall.EpollEvent) {
	if v, err := syscall.GetsockoptInt(int(event.Fd), syscall.SOL_SOCKET, syscall.SO_ERROR); err != nil {
		utils.LOG.Println("Error", err)
	} else {
		utils.LOG.Println("Error val", v)
	}
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
			s.SendTo(packtcp(relay))
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

// SendTo ...
func (s *Stack) SendTo(data []byte) error {

	to := &syscall.SockaddrInet4{Port: int(0), Addr: [4]byte{data[16], data[17], data[18], data[19]}} //[4]byte{dest[0], dest[1], dest[2], dest[
	err := syscall.Sendto((int(s.tun)), data, 0, to)
	if err != nil {
		utils.LOG.Println(fmt.Sprintf("Error: %s %d\n", err.Error(), len(data)))
		return err
	}
	return nil
}

// Close ...
func (s *Stack) Close() {
	s.stop = true
	syscall.Close(s.epfd)
	syscall.Close(s.tun)
	s.epfd = 0
	s.tun = 0
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

	s.t = nil
	s.u = nil
	s.buffer = nil
	s.sendQueue = nil
}
