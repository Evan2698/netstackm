package mobile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/Evan2698/chimney/utils"
	"github.com/Evan2698/netstackm/netcore"
	"golang.org/x/net/proxy"
)

var gstack *netcore.Stack

// StartService ...
func StartService(fd int, proxy string, dns string) bool {
	var err error
	gstack, err = netcore.New(fd)
	if err != nil {
		utils.LOG.Print("create tun stack failed", err)
		return false
	}

	go func() {
		for {
			c, err := gstack.Accept()
			if err != nil {
				utils.LOG.Println("TCP ACCEPT exit!!!")
				break
			}
			go handTCPConnection(c, proxy)
		}
	}()

	go func() {
		for {
			c, err := gstack.AcceptUDP()
			if err != nil {
				utils.LOG.Println("UDP ACCEPT exit!!!")
				break
			}
			go handUDPConnection(c, proxy, dns)
		}
	}()

	return true
}

func handTCPConnection(c *netcore.Connection, url string) {
	defer c.Close()

	dialer, err := proxy.SOCKS5("tcp", url, nil, proxy.Direct)
	if err != nil {
		fmt.Println("Error connecting to proxy:", err)
		return
	}

	host := c.RemoteAddr().String()

	con, err := dialer.Dial("tcp", host)
	if err != nil {
		fmt.Println("Error connecting to proxy:", err)
		return
	}

	defer con.Close()

	go func() {
		var sz [1500]byte

		for {
			n, err := con.Read(sz[:])
			if err != nil {
				utils.LOG.Print("read proxy failed", err)
				break
			}
			_, err = c.Write(sz[:n])
			if err != nil {
				utils.LOG.Print("write tun failed", err)
				break
			}
		}

	}()
	var buffer [1500]byte
	for {
		n, err := c.Read(buffer[:])
		if err != nil {
			utils.LOG.Print("exit", err)
			break
		}

		_, err = con.Write(buffer[:n])
		if err != nil {
			utils.LOG.Print("proxy exit", err)
			break
		}

	}

}

func handUDPConnection(c *netcore.UDPConnection, url string, dns string) {
	defer c.Close()

	con, err := net.Dial("udp", url)
	if err != nil {
		utils.LOG.Println("connect udp failed", err)
		return
	}

	defer con.Close()

	go func() {
		hello := make([]byte, 4096)
		for {
			n, err := con.Read(hello)
			if err != nil {
				utils.LOG.Println("read udp from proxy failed", err)
				break
			}

			_, err = c.Write(hello[:n])
			if err != nil {
				utils.LOG.Println("write udp to tun failed", err)
				break
			}
		}

	}()

	buf := make([]byte, 4000)
	for {
		n, err := c.Read(buf)
		if err != nil {
			utils.LOG.Println("read udp from tun failed", err)
			break
		}

		if strings.Contains(c.RemoteAddr().String(), dns) {

		}

		v := packUDPHeader(buf[:n], c.RemoteAddr())
		_, err = con.Write(v)
		if err != nil {
			utils.LOG.Println("write udp to proxy failed", err)
			break
		}
	}
}

func packUDPHeader(b []byte, addr net.Addr) []byte {

	var out bytes.Buffer
	n := len([]byte(addr.String()))
	sz := make([]byte, 4)
	binary.BigEndian.PutUint32(sz, uint32(n))

	out.Write(sz)
	out.Write([]byte(addr.String()))
	out.Write(b)

	return out.Bytes()
}

// StopService ...
func StopService() {
	gstack.Close()
	gstack = nil
}
