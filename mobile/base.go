package mobile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Evan2698/chimney/utils"
	"github.com/Evan2698/netstackm/dns"
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

	gstack.Start()

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

	utils.LOG.Println("proxy", url)
	dialer, err := proxy.SOCKS5("tcp", url, nil, proxy.Direct)
	if err != nil {
		fmt.Println("Error connecting to proxy:", err)
		return
	}

	host := c.RemoteAddr().String()
	utils.LOG.Println("remote server:", host)

	con, err := dialer.Dial("tcp", host)
	if err != nil {
		fmt.Println("Error connecting to proxy:", err)
		return
	}

	defer con.Close()

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		var sz [1400]byte
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
	var buffer [1400]byte
	for {
		n, err := c.Read(buffer[:])
		if err != nil {
			utils.LOG.Print("exit", err)
			break
		}
		utils.LOG.Println("TCP DATA:", buffer[:n])
		_, err = con.Write(buffer[:n])
		if err != nil {
			utils.LOG.Print("proxy write error", err)
			break
		}

	}

	wg.Wait()
	utils.LOG.Println("TCP exit!!!!")

}

var gcache = dns.NewDNSCache()

func settimeout(con net.Conn, second int) {
	readTimeout := time.Duration(second) * time.Second
	v := time.Now().Add(readTimeout)
	con.SetReadDeadline(v)
	con.SetWriteDeadline(v)
	con.SetDeadline(v)
}

func handUDPConnection(c *netcore.UDPConnection, url string, dns string) {

	defer c.Close()
	con, err := net.Dial("udp", url)
	if err != nil {
		utils.LOG.Println("connect udp failed", err)
		return
	}
	defer func() {
		con.Close()
	}()

	settimeout(con, 120) // set timeout

	buf := make([]byte, 4096)
	n, err := c.Read(buf[:4000])
	if err != nil {
		utils.LOG.Println("read udp from tun failed", err)
		return
	}

	utils.LOG.Print("UDP READ: ", buf[:n])

	if strings.Contains(c.RemoteAddr().String(), dns) {
		answer := gcache.Query(buf[:n])
		if answer != nil {
			data, e := answer.PackBuffer(buf[:])
			if e == nil {
				go func() {
					_, er := c.Write(data)
					utils.LOG.Print("dns response in cache:  ", er)
				}()
				return
			}
		}
	}

	v := packUDPHeader(buf[:n], c.RemoteAddr())
	_, err = con.Write(v)
	if err != nil {
		utils.LOG.Println("write udp to proxy failed", err)
		return
	}

	n, err = con.Read(buf)
	if err != nil {
		utils.LOG.Println("read udp from proxy failed", err)
		return
	}

	raw := buf[:n]
	if strings.Contains(c.RemoteAddr().String(), dns) {
		gcache.Store(raw)
	}

	_, err = c.Write(raw)
	if err != nil {
		utils.LOG.Println("write udp to tun failed", err)
	}

	utils.LOG.Println("X  ----------------exit!")
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
