package connection

import (
	"io"
	"net"
	"strconv"

	"github.com/Evan2698/chimney/utils"
	"github.com/Evan2698/tun2socks/ipv4"
	"github.com/Evan2698/tun2socks/tcp"
)

// CCloser ..
type CCloser interface {
	NotifyClose(srcip, destip net.IP, src, dest uint16)
}

type tcpreactor struct {
	output chan ipv4.IPv4ReaderWriter
	input  chan *ipv4.IPv4
	mgr    *conectmgr
	C      chan netConnectImp
	stop   bool
}

func (r *tcpreactor) Dispatch(pkg *ipv4.IPv4) {
	r.input <- pkg
}

func (r *tcpreactor) run() {
	for {
		select {
		case pkt := <-r.input:
			if pkt.IsStop() {
				utils.LOG.Println("will stop tcp reactor..")
				return
			}

			one, err := tcp.ParseTCP(pkt)
			if err != nil {
				ipv4.Dump(pkt)
				utils.LOG.Println("parse the TCP failed", err)
				continue
			}
			key := makeconnectkey(one.SrcIP, one.DstIP, one.SrcPort, one.DstPort)
			con := r.mgr.getconnect(key)
			if con == nil {
				if one.RST {
					utils.LOG.Print("current tcp package include rst flag", one.DstPort, one.DstIP.To4().String())
					continue
				}
				if !one.SYN {
					rst := rest(one.DstIP, one.SrcIP, one.DstPort, one.SrcPort, one.Sequence, one.Acknowledgment, uint32(len(one.Payload)))
					ipv := packcommontcp(rst)
					r.output <- ipv
					continue
				}
				con = newTCPConnect(r.output, one.SrcIP, one.DstIP, one.SrcPort, one.DstPort, r)
				con.Dispatch(one)
				r.mgr.push(key, con)
				r.C <- con
			} else {
				con.Dispatch(one)
			}
		}

	}
}

func makeconnectkey(srcip, destip net.IP, src, dest uint16) string {
	v := net.JoinHostPort(srcip.To4().String(), strconv.Itoa(int(src)))
	k := net.JoinHostPort(destip.To4().String(), strconv.Itoa(int(dest)))
	return k + "-" + v
}

func (r *tcpreactor) Close() {
	r.stop = true
	r.mgr.removeall()
	close(r.input)
	close(r.C)
}

func (r *tcpreactor) NotifyClose(srcip, destip net.IP, src, dest uint16) {
	key := makeconnectkey(srcip, destip, src, dest)
	r.mgr.delete(key)
}

func (r *tcpreactor) WaitConnect() (NetConnect, error) {

	if r.stop {
		return nil, io.EOF
	}

	connect := <-r.C

	return connect, nil
}

// newTCPReactor ...
func newTCPReactor(ch chan ipv4.IPv4ReaderWriter) ConnectManager {

	v := &tcpreactor{
		output: ch,
		input:  make(chan *ipv4.IPv4, 500),
		mgr: &conectmgr{
			mgr: make(map[string]netConnectImp),
		},
		C: make(chan netConnectImp, 100),
	}
	go v.run()
	return v
}
