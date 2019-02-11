package tun2core

import (
	"bytes"
	"encoding/binary"
	"net"

	"github.com/Evan2698/chimney/utils"
	"github.com/Evan2698/tun2socks/connection"
	"github.com/Evan2698/tun2socks/ipv4"
	"golang.org/x/net/proxy"
)

var listen connection.Listener

// Start ..
func Start(fd int, proxy string, dns string) error {

	listen = connection.NewListen()
	err := listen.Bind(fd)
	if err != nil {
		utils.LOG.Println("bind failed", err)
		return err
	}

	go func() {
		tcp, err := listen.ListenTCP(nil)
		for err != nil {
			go handletcp(tcp, proxy)
			tcp, err = listen.ListenTCP(nil)
			if err != nil {
				utils.LOG.Println("listen TCP failed", err)
				break
			}
		}
	}()

	go func() {
		udp, err := listen.ListenUDP(nil)
		for err != nil {
			go handleudp(udp, proxy, dns)
			udp, err = listen.ListenUDP(nil)
			if err != nil {
				utils.LOG.Println("listen UDP failed", err)
				break
			}
		}

	}()

	return nil
}

func handletcp(tcp connection.NetConnect, url string) {
	defer func() {
		tcp.Close()
	}()

	dialer, err := proxy.SOCKS5("tcp", url, nil, proxy.Direct)
	if err != nil {
		utils.LOG.Println("can not connect socks5 proxy server~", err)
		return
	}

	host := tcp.GetRemoteAddress().String()

	con, err := dialer.Dial("tcp", host)
	if err != nil {
		utils.LOG.Println("can not connect host failed~", err)
		return
	}

	defer func() {
		con.Close()
	}()

	go func() {

		buf := make([]byte, ipv4.MTU)
		for {
			u := tcp.GetWriteBytes()
			c, re := con.Read(buf[:u])
			if re != nil {
				utils.LOG.Println("TCP socks5 read failed", err)
				break
			}
			we := tcp.Write(buf[:c])
			if we != nil {
				utils.LOG.Println("TCP write 2 tun failed", err)
				break
			}
		}

	}()

	for {
		r, re := tcp.Read()
		if re != nil {
			utils.LOG.Println("read tun failed ", err)
			break
		}
		_, we := con.Write(r)
		if we != nil {
			utils.LOG.Println("write socks5 failed ", err)
			break
		}
	}

}

var cache = &dnsCache{
	storage: make(map[string]*dnsCacheEntry),
}

func handleudp(udp connection.NetConnect, proxy string, dns string) {

	defer func() {
		udp.Close()
	}()

	p, err := net.Dial("udp", proxy)
	if err != nil {
		utils.LOG.Println("conncet udp failed", err)
		return
	}

	defer func() {
		p.Close()
	}()

	c, err := udp.Read()
	if err != nil {
		utils.LOG.Println("udp read failed", err)
		return
	}

	if dns == udp.GetRemoteAddress().String() {
		var buf [1024]byte
		answer := cache.query(c)
		if answer != nil {
			data, e := answer.PackBuffer(buf[:])
			if e == nil {
				udp.Write(data)
				return
			}
		}
	}

	s := packudp(c, udp.GetRemoteAddress())
	p.Write(s)

	os := make([]byte, 4096)
	n, err := p.Read(os)
	if err != nil {
		utils.LOG.Println("udp read failed o", err)
		return
	}

	udp.Write(os[:n])

	if dns == udp.GetRemoteAddress().String() {
		cache.store(os[:n])
	}
}

func packudp(c []byte, a *net.TCPAddr) []byte {
	addr := a.String()
	var buf bytes.Buffer
	var int2bytebuffer bytes.Buffer
	l := uint32(len([]byte(addr)))
	binary.Write(&int2bytebuffer, binary.BigEndian, l)
	buf.Write(int2bytebuffer.Bytes())
	buf.Write([]byte(addr))
	buf.Write(c)
	return buf.Bytes()
}

// Stop ..
func Stop() {
	if listen != nil {
		listen.Close()
		listen = nil
	}
}
