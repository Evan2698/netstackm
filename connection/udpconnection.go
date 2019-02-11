package connection

import (
	"container/list"
	"errors"
	"io"
	"net"

	"github.com/Evan2698/tun2socks/ipv4"
	"github.com/Evan2698/tun2socks/udp"
)

type udpConnect struct {
	input   chan interface{}
	srcport uint16
	dstport uint16
	srcIP   net.IP
	dstIP   net.IP
	output  chan ipv4.IPv4ReaderWriter
}

func (u *udpConnect) GetLocalAddress() *net.TCPAddr {
	v := net.TCPAddr{
		IP:   u.srcIP.To4(),
		Port: int(u.srcport),
	}
	return &v
}

func (u *udpConnect) GetRemoteAddress() *net.TCPAddr {
	v := net.TCPAddr{
		IP:   u.dstIP.To4(),
		Port: int(u.dstport),
	}
	return &v
}

func (u *udpConnect) Read() ([]byte, error) {
	if u.input == nil {
		return nil, io.EOF
	}

	p := <-u.input

	udp, _ := p.(*udp.UDP)
	if udp.IsStop() {
		return nil, io.EOF
	}

	return udp.Payload, nil
}

func (u *udpConnect) Write(b []byte) error {

	wl := len(b)
	if wl > 0 {

		ud := &udp.UDP{
			SrcPort: u.dstport,
			DstPort: u.srcport,
			Payload: b,
		}
		content := ud.ToBytes(u.dstIP, u.srcIP)

		ipvs := generateipvs(content, u.dstIP, u.srcIP, u.dstport, u.srcport)

		go u.sendudp(ipvs)

		return nil
	}

	return errors.New("write failed")
}

func (u *udpConnect) sendudp(l *list.List) {
	for e := l.Front(); e != nil; e = e.Next() {
		var f *ipv4.IPv4
		f, _ = e.Value.(*ipv4.IPv4)
		u.output <- f
	}
}

func generateipvs(c []byte, src, dst net.IP, sport, dport uint16) *list.List {
	l := list.New()
	n := len(c)
	first := &ipv4.IPv4{}
	if n > (ipv4.MTU - 20) {
		first.Flags = 1
	}

	first.Version = 4
	first.TTL = 64
	first.Protocol = ipv4.UDP
	first.SrcIP = src
	first.DstIP = dst
	first.Identification = ipv4.GeneratorIPID()
	l.PushBack(first)

	offset := 0

	if first.Flags == 1 {
		first.PayLoad = c[:ipv4.MTU-20]
		rest := c[ipv4.MTU-20:]
		lr := len(rest)
		for lr > 0 {
			tmp := &ipv4.IPv4{}
			tmp.Version = first.Version
			tmp.TTL = first.TTL
			tmp.SrcIP = first.SrcIP
			tmp.DstIP = first.DstIP
			tmp.Protocol = first.Protocol
			tmp.FragmentOffset = uint16(offset)
			tmp.Identification = first.Identification
			offset += ((ipv4.MTU - 20) / 8)
			if lr > ipv4.MTU-20 {
				tmp.Flags = 1
				tmp.PayLoad = rest[:ipv4.MTU-20]
				rest = rest[ipv4.MTU-20:]
				lr = len(rest)

			} else {
				tmp.Flags = 0
				tmp.PayLoad = rest[:]
				lr = 0
			}

			l.PushBack(tmp)
		}

	} else {
		first.PayLoad = c
	}

	return l
}

func (u *udpConnect) GetWriteBytes() int32 {
	return 0
}

func (u *udpConnect) Close() {
	close(u.input)
	u.input = nil
}

func (u *udpConnect) Dispatch(d interface{}) {
	u.input <- d
}

func newUDPConnect(o chan ipv4.IPv4ReaderWriter, src, dst net.IP, sport, dport uint16, n CCloser) netConnectImp {

	v := &udpConnect{
		input:   make(chan interface{}, 5),
		output:  o,
		srcIP:   src,
		dstIP:   dst,
		srcport: sport,
		dstport: dport,
	}

	return v
}
