package netcore

import (
	"net"

	"github.com/Evan2698/netstackm/ipv4"
	"github.com/Evan2698/netstackm/tcp"
)

func synack(c *State) *tcp.TCP {
	pak := tcp.Newtcp()
	pak.SrcIP = c.DestIP
	pak.DstIP = c.SrcIP
	pak.SrcPort = c.DestPort
	pak.DstPort = c.SrcPort
	pak.SYN = true
	pak.ACK = true
	pak.Sequence = c.SendNext
	pak.Acknowledgment = c.RecvNext
	pak.WndSize = uint16(c.recvWindow)
	pak.Options = make([]*tcp.TCPOption, 1)

	item := tcp.NewTCPOption()
	item.Type = 2
	item.Length = 4
	item.Data = []byte{0x5, 0xb4}
	pak.Options[0] = item

	return pak
}

func rst(sip, dip net.IP, sport, dport uint16, seq, ack uint32, payloadlen uint32) *tcp.TCP {
	pak := tcp.Newtcp()
	pak.SrcIP = dip
	pak.DstIP = sip
	pak.SrcPort = dport
	pak.DstPort = sport
	pak.WndSize = uint16(MAX_RECV_WINDOW)
	pak.RST = true
	pak.ACK = true
	pak.Sequence = 0
	pak.Acknowledgment = seq + payloadlen
	if pak.Acknowledgment == seq {
		pak.Acknowledgment = pak.Acknowledgment + 1
	}
	if ack != 0 {
		pak.Sequence = ack
	}

	return pak
}

func packtcp(tcp *tcp.TCP) []byte {
	ip := ipv4.NewIPv4()
	ip.Version = 4
	ip.Protocol = ipv4.IPProtocolTCP
	ip.Identification = ipv4.GeneratorIPID()
	ip.SrcIP = tcp.SrcIP
	ip.DstIP = tcp.DstIP
	ip.TTL = 128
	ip.PayLoad = tcp.ToBytes()

	return ip.ToBytes()
}

func validAck(ack, nextseq uint32) bool {
	ret := (ack == nextseq)
	return ret
}

func validSeq(seq, nextseq uint32) bool {
	ret := (seq == nextseq)
	return ret
}

func ack(current *State) *tcp.TCP {

	pak := tcp.Newtcp()
	pak.SrcIP = current.DestIP
	pak.DstIP = current.SrcIP
	pak.SrcPort = current.DestPort
	pak.DstPort = current.SrcPort
	pak.WndSize = uint16(current.recvWindow)
	pak.ACK = true
	pak.Sequence = current.SendNext
	pak.Acknowledgment = current.RecvNext

	return pak
}

func finAck(current *State) *tcp.TCP {
	pak := tcp.Newtcp()
	pak.SrcIP = current.DestIP
	pak.DstIP = current.SrcIP
	pak.SrcPort = current.DestPort
	pak.DstPort = current.SrcPort
	pak.WndSize = uint16(current.recvWindow)
	pak.FIN = true
	pak.ACK = true
	pak.Sequence = current.SendNext
	pak.Acknowledgment = current.RecvNext
	current.SendNext = current.SendNext + 1
	return pak
}

func payload(current *State, data []byte) *tcp.TCP {

	pak := tcp.Newtcp()
	pak.SrcIP = current.DestIP
	pak.DstIP = current.SrcIP
	pak.SrcPort = current.DestPort
	pak.DstPort = current.SrcPort
	pak.WndSize = uint16(current.recvWindow)
	pak.FIN = true
	pak.PSH = true
	pak.Sequence = current.SendNext
	pak.Acknowledgment = current.RecvNext
	pak.Payload = data
	return pak
}
