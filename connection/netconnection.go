package connection

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Evan2698/chimney/utils"

	"github.com/Evan2698/tun2socks/ipv4"
	"github.com/Evan2698/tun2socks/tcp"
)

// NetConnect ...
type NetConnect interface {
	GetLocalAddress() *net.TCPAddr
	GetRemoteAddress() *net.TCPAddr
	Read() ([]byte, error)
	Write([]byte) error
	GetWriteBytes() int32
	Close()
}

type netConnectImp interface {
	NetConnect
	Dispatch(d interface{})
}

type tcpState byte

const (
	LISTEN tcpState = 0x1

	//SYN_RCVD ..
	SYN_RCVD tcpState = 0x2

	// ESTABLISHED ..
	ESTABLISHED tcpState = 0x3

	// FIN_WAIT_1 ..
	FIN_WAIT_1 tcpState = 0x4

	// FIN_WAIT_2 ..
	FIN_WAIT_2 tcpState = 0x5

	// CLOSING ..
	CLOSING tcpState = 0x6

	// LAST_ACK ..
	LAST_ACK tcpState = 0x7

	// TIME_WAIT ..
	TIME_WAIT tcpState = 0x8

	// CLOSED ..
	CLOSED tcpState = 0x9

	// MAX_RECV_WINDOW ..
	MAX_RECV_WINDOW int = 65535

	// MAX_SEND_WINDOW ..
	MAX_SEND_WINDOW int = 65535
)

type tcpConnect struct {
	state       tcpState
	srcport     uint16
	dstport     uint16
	srcIP       net.IP
	dstIP       net.IP
	output      chan ipv4.IPv4ReaderWriter
	input       chan interface{}
	recvWindow  int32
	sendWindow  int32
	sendWndCond *sync.Cond
	nxtSeq      uint32
	rcvNxtSeq   uint32
	lastAck     uint32

	// read chan
	readch chan *tcp.TCP

	notifier CCloser
}

func newTCPConnect(o chan ipv4.IPv4ReaderWriter, src, dst net.IP, sport, dport uint16, n CCloser) netConnectImp {
	v := &tcpConnect{
		output:      o,
		state:       CLOSED,
		input:       make(chan interface{}, 100),
		srcIP:       src,
		dstIP:       dst,
		srcport:     sport,
		dstport:     dport,
		sendWindow:  int32(MAX_SEND_WINDOW),
		recvWindow:  int32(MAX_RECV_WINDOW),
		sendWndCond: &sync.Cond{L: &sync.Mutex{}},
		readch:      make(chan *tcp.TCP, 100),
		notifier:    n,
	}

	go v.run()

	return v
}

func (tcpc *tcpConnect) updateSendWindow(pkt *tcp.TCP) {
	atomic.StoreInt32(&tcpc.sendWindow, int32(pkt.WndSize))
	tcpc.sendWndCond.Signal()
}

func (tcpc *tcpConnect) updateState(pkt *tcp.TCP) {
	switch tcpc.state {
	case LISTEN:
		if pkt.SYN {
			tcpc.rcvNxtSeq = pkt.Sequence + 1
			tcpc.nxtSeq = 1
			// send SYN ACK
			tmp := synack(pkt, uint32(atomic.LoadInt32(&tcpc.recvWindow)), tcpc.nxtSeq, tcpc.rcvNxtSeq)
			tcpc.send2tun(tmp)
			tcpc.nxtSeq++
			tcpc.state = SYN_RCVD

		} else {
			utils.LOG.Print("can not handle TCP package:", pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort)
		}
	case CLOSED:
		{
			utils.LOG.Print("CLOSED:", pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort)
		}
	case SYN_RCVD:
		if !(validack(pkt, tcpc) && validseq(pkt, tcpc)) {
			if !pkt.RST {
				tmpt := rest(pkt.SrcIP, pkt.DstIP, pkt.SrcPort, pkt.DstPort, pkt.Sequence, pkt.Acknowledgment, uint32(len(pkt.Payload)))
				tcpc.send2tun(tmpt)
			}
		} else {
			if pkt.RST {
				utils.LOG.Println("SYN_RCVD: ", "RST packet")
				return
			}
			if !pkt.ACK {
				utils.LOG.Println("SYN_RCVD: ", "non-ack packet!")
				return
			}
			tcpc.state = ESTABLISHED
			payloadLen := len(pkt.Payload)
			if payloadLen > 0 {
				tcpc.sendreadchannel(pkt)
			}
		}
	case ESTABLISHED:
		if !validseq(pkt, tcpc) {
			tmp := ack(pkt, tcpc.nxtSeq, tcpc.rcvNxtSeq, uint16(atomic.LoadInt32(&tcpc.recvWindow)))
			tcpc.send2tun(tmp)
			return
		}
		if !pkt.RST {
			utils.LOG.Println("ESTABLISHED: ", "RST packet!")
			tcpc.state = CLOSED
			return
		}

		if !pkt.ACK {
			utils.LOG.Println("ESTABLISHED: ", "non-ack packet!")
			return
		}
		payloadLen := len(pkt.Payload)
		if payloadLen > 0 {
			utils.LOG.Println("ESTABLISHED: ", "non-ack packet!")
			tcpc.sendreadchannel(pkt)
		}

		if pkt.FIN {
			tcpc.rcvNxtSeq++
			finack(pkt, tcpc.nxtSeq, tcpc.rcvNxtSeq, uint16(atomic.LoadInt32(&tcpc.recvWindow)))
			tcpc.nxtSeq++
			tcpc.state = LAST_ACK
		}

	case FIN_WAIT_1:
		if !validseq(pkt, tcpc) {
			return
		}

		if pkt.RST {
			utils.LOG.Println("FIN_WAIT_1: ", "RST packet!")
			return
		}
		if !pkt.ACK {
			utils.LOG.Println("FIN_WAIT_1: ", "non-ack packet!")
			return
		}

		if pkt.FIN {
			tcpc.rcvNxtSeq++
			tmp := ack(pkt, tcpc.nxtSeq, tcpc.rcvNxtSeq, uint16(atomic.LoadInt32(&tcpc.recvWindow)))
			tcpc.send2tun(tmp)
			if pkt.ACK && validack(pkt, tcpc) {
				tcpc.state = TIME_WAIT
			} else {
				tcpc.state = CLOSING
			}
		} else {
			tcpc.state = FIN_WAIT_2
		}

	case FIN_WAIT_2:
		if !(validseq(pkt, tcpc) && validack(pkt, tcpc)) {
			utils.LOG.Println("FIN_WAIT_2: ", "skip the packet!!")
			return
		}
		// connection ends by valid RST
		if pkt.RST {
			utils.LOG.Println("FIN_WAIT_2: ", "RST packet!")
			return
		}
		// ignore non-FIN non-ACK packets
		if !pkt.ACK || !pkt.FIN {
			utils.LOG.Println("FIN_WAIT_2: ", "ignore non-FIN non-ACK packets")
			return
		}
		tcpc.rcvNxtSeq++
		tmp := ack(pkt, tcpc.nxtSeq, tcpc.rcvNxtSeq, uint16(atomic.LoadInt32(&tcpc.recvWindow)))
		tcpc.send2tun(tmp)
		tcpc.state = TIME_WAIT

	case TIME_WAIT:
	case CLOSING:
		if !(validseq(pkt, tcpc) && validack(pkt, tcpc)) {
			utils.LOG.Println("CLOSING: ", "skip the packet!!")
			return
		}
		// connection ends by valid RST
		if pkt.RST {
			utils.LOG.Println("CLOSING: ", "RST packet!!")
			return
		}
		// ignore non-ACK packets
		if !pkt.ACK {
			utils.LOG.Println("CLOSING: ", "ignore non-ACK packets")
			return
		}
		tcpc.state = TIME_WAIT

	case LAST_ACK:
		if !(validseq(pkt, tcpc) && validack(pkt, tcpc)) {
			utils.LOG.Println("LAST_ACK: ", "skip the packet!!")
			return
		}
		// ignore non-ACK packets
		if !pkt.ACK {
			utils.LOG.Println("LAST_ACK: ", "ignore non-ACK packets")
			return
		}
		// connection ends
		tcpc.state = CLOSED
	}

	if tcpc.state == CLOSED || tcpc.state == TIME_WAIT {
		tcpc.notifier.NotifyClose(tcpc.srcIP, tcpc.dstIP, tcpc.srcport, tcpc.dstport)
	}
}

func (tcpc *tcpConnect) sendreadchannel(pkt *tcp.TCP) {
	payloadLen := len(pkt.Payload)
	tcpc.rcvNxtSeq += uint32(payloadLen)
	// reduce window when recved
	wnd := atomic.LoadInt32(&tcpc.recvWindow)
	wnd -= int32(payloadLen)
	if wnd < 0 {
		wnd = 0
	}
	atomic.StoreInt32(&tcpc.recvWindow, wnd)
	tcpc.readch <- pkt
}

func (tcpc *tcpConnect) send2tun(pkt *tcp.TCP) {

	if pkt.ACK {
		tcpc.lastAck = pkt.Acknowledgment
	}
	ip := packcommontcp(pkt)
	tcpc.output <- ip
}

func (tcpc *tcpConnect) run() {
	timeout := time.NewTimer(5 * time.Minute)
	for {
		k := <-tcpc.input
		t, _ := k.(*tcp.TCP)

		if t.IsStop() {
			utils.LOG.Println("this connection will exit!")
			break
		}

		tcpc.updateSendWindow(t)
		tcpc.updateState(t)
		select {
		case <-timeout.C:
			tcpc.state = TIME_WAIT
			return
		default:
		}

	}
}

func (tcpc *tcpConnect) GetLocalAddress() *net.TCPAddr {
	v := net.TCPAddr{
		IP:   tcpc.srcIP.To4(),
		Port: int(tcpc.srcport),
	}
	return &v
}
func (tcpc *tcpConnect) GetRemoteAddress() *net.TCPAddr {
	v := net.TCPAddr{
		IP:   tcpc.dstIP.To4(),
		Port: int(tcpc.dstport),
	}
	return &v
}

func (tcpc *tcpConnect) Read() ([]byte, error) {
	if tcpc.state <= ESTABLISHED {
		one := <-tcpc.readch
		wnd := atomic.LoadInt32(&tcpc.recvWindow)
		wnd += int32(len(one.Payload))
		if wnd > int32(MAX_RECV_WINDOW) {
			wnd = int32(MAX_RECV_WINDOW)
		}
		atomic.StoreInt32(&tcpc.recvWindow, wnd)

		return one.Payload, nil
	}
	return nil, errors.New(formatstate(tcpc.state))
}
func (tcpc *tcpConnect) Write(b []byte) error {

	if tcpc.state <= ESTABLISHED {

		n := len(b)
		if n > 0 {
			var wnd int32
			wnd = atomic.LoadInt32(&tcpc.sendWindow)
			nxt := wnd - int32(n)
			if nxt < 0 {
				nxt = 0
			}
			// if sendWindow does not equal to wnd, it is already updated by a
			// received pkt from TUN
			atomic.CompareAndSwapInt32(&tcpc.sendWindow, wnd, nxt)
			tmp := payload(tcpc.dstIP, tcpc.srcIP, tcpc.dstport, tcpc.srcport, tcpc.nxtSeq, tcpc.rcvNxtSeq,
				uint16(atomic.LoadInt32(&tcpc.recvWindow)), b)
			tcpc.send2tun(tmp)
			tcpc.nxtSeq = tcpc.nxtSeq + uint32(n)
		}
	}
	return errors.New(formatstate(tcpc.state))
}
func (tcpc *tcpConnect) Close() {

	flag := &tcp.TCP{
		Stop: true,
	}
	tcpc.input <- flag
	tcpc.state = CLOSED
	close(tcpc.input)
	close(tcpc.readch)
}

func (tcpc *tcpConnect) GetWriteBytes() int32 {
	var wnd int32
	var cur int32
	wnd = atomic.LoadInt32(&tcpc.sendWindow)

	if wnd <= 0 {
		for wnd <= 0 {
			tcpc.sendWndCond.L.Lock()
			tcpc.sendWndCond.Wait()
			wnd = atomic.LoadInt32(&tcpc.sendWindow)
		}
		tcpc.sendWndCond.L.Unlock()
	}

	cur = wnd
	if cur > int32(ipv4.MTU)-40 {
		cur = int32(ipv4.MTU) - 40
	}

	return cur
}

func (tcpc *tcpConnect) Dispatch(d interface{}) {
	tcpc.state = LISTEN
	tcpc.input <- d
}
