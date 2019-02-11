package connection

import (
	"net"
	"os"

	"github.com/Evan2698/chimney/utils"

	"github.com/Evan2698/tun2socks/tcp"
	"github.com/Evan2698/tun2socks/udp"
)

// ListenFilter ..
type ListenFilter interface {
	FilterTCP(tcp *tcp.TCP) error
	FilterUDP(udp *udp.UDP) error
}

// Listener ...
type Listener interface {
	Bind(fd int) error
	ListenTCP(l ListenFilter) (NetConnect, error)
	ListenUDP(l ListenFilter) (NetConnect, error)
	Close()
}

type listen struct {
	r netStackReactor
}

func (l *listen) Bind(fd int) error {

	f := os.NewFile((uintptr)(fd), "")
	filecon, err := net.FileConn(f)
	if err != nil {
		utils.LOG.Println("create file connection failed, ", err)
		return err
	}
	l.r = newReactor(filecon)
	go l.r.Run()
	return nil
}

func (l *listen) ListenTCP(f ListenFilter) (NetConnect, error) {
	return l.r.Waittcp()
}

func (l *listen) ListenUDP(f ListenFilter) (NetConnect, error) {
	return l.r.Waitudp()
}

func (l *listen) Close() {
	if l.r != nil {
		l.r.Stop()
		l.r = nil
	}
}

// NewListen ..
func NewListen() Listener {
	l := &listen{}
	return l
}
