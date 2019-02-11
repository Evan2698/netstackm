package connection

import (
	"io"
	"net"

	"github.com/Evan2698/chimney/utils"
	"github.com/Evan2698/tun2socks/ipv4"
	"github.com/Evan2698/tun2socks/udp"
)

type udpreactor struct {
	output chan ipv4.IPv4ReaderWriter
	input  chan *ipv4.IPv4
	C      chan netConnectImp
	stop   bool
}

func (r *udpreactor) Dispatch(pkg *ipv4.IPv4) {
	r.input <- pkg
}

func (r *udpreactor) Close() {
	v := &ipv4.IPv4{
		Version: tunstopmarker,
	}
	r.input <- v
	r.stop = true
	close(r.input)
	close(r.C)
}

func (r *udpreactor) run() {

	for {
		ippkt := <-r.input
		if ippkt.IsStop() {
			break
		}
		pkg := &udp.UDP{}
		err := pkg.TryParse(ippkt.PayLoad)
		if err != nil {
			utils.LOG.Println("parse UDP failed!")
			continue
		}
		udpC := newUDPConnect(r.output, ippkt.SrcIP, ippkt.DstIP, pkg.SrcPort, pkg.DstPort, r)
		udpC.Dispatch(pkg)
		r.C <- udpC
	}

}

func (r *udpreactor) NotifyClose(srcip, destip net.IP, src, dest uint16) {

}

func (r *udpreactor) WaitConnect() (NetConnect, error) {
	if r.stop {
		return nil, io.EOF
	}

	a := <-r.C

	return a, nil
}

// newUDPReactor ...
func newUDPReactor(ch chan ipv4.IPv4ReaderWriter) ConnectManager {

	v := &udpreactor{
		output: ch,
		input:  make(chan *ipv4.IPv4, 300),
		C:      make(chan netConnectImp, 100),
		stop:   false,
	}

	go v.run()

	return v
}
