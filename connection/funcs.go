package connection

import (
	"net"

	"github.com/Evan2698/tun2socks/ipv4"
	"github.com/Evan2698/tun2socks/tcp"
)

func packcommontcp(tcp *tcp.TCP) *ipv4.IPv4 {
	ip := &ipv4.IPv4{}
	ip.Version = 4
	ip.Protocol = ipv4.TCP
	ip.TTL = 128
	ip.IHL = 5
	ip.PayLoad = tcp.ToBytes()
	ip.Length = uint16(len(ip.PayLoad)) + 20
	ip.Identification = ipv4.GeneratorIPID()
	ip.SrcIP = tcp.SrcIP
	ip.DstIP = tcp.DstIP
	return ip
}

func rest(srcip, dstip net.IP, srcport, dstport uint16, seq, ack uint32, paylen uint32) *tcp.TCP {
	tcp := &tcp.TCP{}
	tcp.SrcIP = srcip
	tcp.DstIP = dstip
	tcp.SrcPort = srcport
	tcp.DstPort = dstport
	tcp.Sequence = 0
	tcp.Acknowledgment = ack

	tcp.Acknowledgment = seq + paylen
	if tcp.Acknowledgment == seq {
		tcp.Acknowledgment = tcp.Acknowledgment + 1
	}
	if ack != 0 {
		tcp.Sequence = ack
	}

	tcp.WndSize = uint16(MAX_RECV_WINDOW)
	tcp.RST = true
	tcp.ACK = true
	return tcp
}

func synack(ori *tcp.TCP, wnd, next, rnext uint32) *tcp.TCP {
	tcppack := &tcp.TCP{}
	tcppack.SrcIP = ori.DstIP
	tcppack.DstIP = ori.SrcIP
	tcppack.SrcPort = ori.DstPort
	tcppack.DstPort = ori.SrcPort
	tcppack.Sequence = next
	tcppack.Acknowledgment = rnext

	// max segment maxsize 1460
	tcppack.Options = make([]*tcp.TCPOption, 1)
	tcppack.Options[0] = &tcp.TCPOption{
		Type:   2,
		Length: 4,
		Data:   []byte{0x5, 0xb4},
	}

	tcppack.WndSize = uint16(wnd)

	tcppack.ACK = true
	tcppack.SYN = true

	return tcppack

}

func validseq(ori *tcp.TCP, c *tcpConnect) bool {
	ret := ori.Sequence == c.rcvNxtSeq
	return ret
}

func validack(ori *tcp.TCP, c *tcpConnect) bool {
	ret := (ori.Acknowledgment == c.nxtSeq)
	return ret
}

func ack(ori *tcp.TCP, seg, ack uint32, wnd uint16) *tcp.TCP {
	tcppack := &tcp.TCP{}
	tcppack.SrcIP = ori.DstIP
	tcppack.DstIP = ori.SrcIP
	tcppack.SrcPort = ori.DstPort
	tcppack.DstPort = ori.SrcPort
	tcppack.Sequence = seg
	tcppack.Acknowledgment = ack
	tcppack.WndSize = wnd
	tcppack.ACK = true
	return tcppack

}

func finack(ori *tcp.TCP, seg, ack uint32, wnd uint16) *tcp.TCP {
	tcppack := &tcp.TCP{}
	tcppack.SrcIP = ori.DstIP
	tcppack.DstIP = ori.SrcIP
	tcppack.SrcPort = ori.DstPort
	tcppack.DstPort = ori.SrcPort
	tcppack.Sequence = seg
	tcppack.Acknowledgment = ack
	tcppack.WndSize = wnd
	tcppack.FIN = true
	tcppack.ACK = true
	return tcppack
}

func payload(srcip, destip net.IP, srcport, destport uint16, seg, ack uint32, wnd uint16, data []byte) *tcp.TCP {
	tcppack := &tcp.TCP{}
	tcppack.SrcIP = srcip
	tcppack.DstIP = destip
	tcppack.SrcPort = srcport
	tcppack.DstPort = destport
	tcppack.Sequence = seg
	tcppack.Acknowledgment = ack
	tcppack.WndSize = wnd
	tcppack.PSH = true
	tcppack.ACK = true
	tcppack.Payload = data
	return tcppack
}

func formatstate(state tcpState) string {

	switch state {
	case LISTEN:
		return "LISTEN"
	case CLOSED:
		return "CLOSED"
	case SYN_RCVD:
		return "SYN_RCVD"
	case ESTABLISHED:
		return "ESTABLISHED"
	case FIN_WAIT_1:
		return "FIN_WAIT_1"
	case FIN_WAIT_2:
		return "FIN_WAIT_2"
	case CLOSING:
		return "CLOSING"
	case LAST_ACK:
		return "LAST_ACK"
	case TIME_WAIT:
		return "TIME_WAIT"
	default:
		return "UNKNOWN"
	}
}
