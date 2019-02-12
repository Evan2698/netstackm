package connection

import (
	"io"
	"net"
	"time"

	"github.com/Evan2698/chimney/utils"

	"github.com/Evan2698/tun2socks/ipv4"
)

const (
	tunstopmarker = 0xff
	stopip        = "11.11.11.11"
	stopfull      = "11.11.11.11:11111"
)

type netStackReactor interface {
	Run()
	Stop()

	Waittcp() (NetConnect, error)
	Waitudp() (NetConnect, error)
}

// Dispatcher ..
type Dispatcher interface {
	Dispatch(pkg *ipv4.IPv4)
}

// ConnectManager ..
type ConnectManager interface {
	Dispatcher
	WaitConnect() (NetConnect, error)
	Close()
}

type reactor struct {
	tun     io.ReadWriteCloser
	writeCh chan ipv4.IPv4ReaderWriter
	tcp     ConnectManager
	udp     ConnectManager
}

func (r *reactor) Run() {
	go func() {
		for {
			pkt := <-r.writeCh
			if pkt.IsStop() {
				utils.LOG.Println("tun reactor will stop.!!!! bye")
				break
			}
			n, err := r.tun.Write(pkt.ToBytes())
			if err != nil {
				utils.LOG.Println("write tun device failed,", err, n)
			}
			pkt.Close()
		}
	}()

	for {
		var full = make([]byte, ipv4.MTU)
		n, err := r.tun.Read(full)
		if err != nil {
			utils.LOG.Println("read from tun device failed!", err, n)
		}

		pkg := &ipv4.IPv4{}
		err = pkg.TryParseBasicHeader(full[:20])
		if err != nil {
			utils.LOG.Println("parse ip header failed", err)
			continue
		}

		if int(pkg.Length) > ipv4.MTU {
			utils.LOG.Println("IP package format error!!!", err)
			break
		}

		err = pkg.TryParseBody(full[20:n])
		if err != nil {
			utils.LOG.Println("parse ip body failed", err)
			continue
		}

		if r.isStopMarker(pkg) {
			utils.LOG.Println("parse ip body failed", err)
			break
		}

		if (pkg.Flags&0x1) != 0 || pkg.FragmentOffset != 0 {

			finish := ipv4.Merge(pkg)
			if !finish {
				continue
			} else {
				pkg = ipv4.GetHugPkg(pkg.Identification)
				utils.LOG.Println("A huge pkg is: payload=", len(pkg.PayLoad))
			}
		}

		switch pkg.Protocol {
		case ipv4.TCP:
			r.tcp.Dispatch(pkg)
		case ipv4.UDP:
			r.udp.Dispatch(pkg)
		default:
			utils.LOG.Print("other protocol: ", pkg.Protocol)
			pkg.Close()
		}
	}
}

func (r *reactor) isStopMarker(pkg *ipv4.IPv4) bool {

	if pkg.DstIP.To4().String() == stopip {
		return true
	}
	return false
}

func (r *reactor) Stop() {
	stop := &ipv4.IPv4{
		Version: tunstopmarker,
	}
	r.writeCh <- stop

	r.tcp.Dispatch(stop)
	r.udp.Dispatch(stop)

	net.Dial("udp", stopfull)

	if r.writeCh != nil {
		close(r.writeCh)
		r.writeCh = nil
	}

	time.Sleep(time.Second * 2)

	if r.tcp != nil {
		r.tcp.Close()
		r.tcp = nil
	}

	if r.udp != nil {
		r.udp.Close()
		r.udp = nil
	}

	if r.tun != nil {
		r.tun.Close()
		r.tun = nil
	}
}

func (r *reactor) Waittcp() (NetConnect, error) {
	return r.tcp.WaitConnect()
}
func (r *reactor) Waitudp() (NetConnect, error) {
	return r.udp.WaitConnect()
}

func newReactor(t io.ReadWriteCloser) netStackReactor {
	r := &reactor{
		tun:     t,
		writeCh: make(chan ipv4.IPv4ReaderWriter, 100),
	}
	r.tcp = newTCPReactor(r.writeCh)
	r.udp = newUDPReactor(r.writeCh)
	return r
}
