package tcp

import (
	"net"
	"testing"

	"github.com/Evan2698/netstackm/ipv4"
)

/*func Test_TCP(t *testing.T) {

	var zijie = []byte{69, 0, 0, 60, 63, 93, 64, 0, 64, 6, 205, 60, 11, 11, 12, 12, 11, 11, 12, 1, 207, 202, 0, 80, 255, 186, 111, 12, 0, 0, 0, 0, 160, 2, 114, 16, 86, 170, 0, 0, 2, 4, 5, 180, 4, 2, 8, 10, 26, 116, 247, 204, 0, 0, 0, 0, 1, 3, 3, 7}

	t.Log("A", zijie)

	ipp := ipv4.NewIPv4()
	ipp.TryParseBasicHeader(zijie[:20])
	ipp.TryParseBody(zijie[20:])
	t.Log("---------------------------")
	t.Log(ipp.PayLoad)
	t.Log("---------------------------")
	ptk := Newtcp()
	ptk.TryParse(ipp.PayLoad)
	ptk.Dump()
	ptk.SrcIP = ipp.SrcIP
	ptk.DstIP = ipp.DstIP
	t.Log(ptk.ToBytes())
	t.Log("B", ipp.ToBytes())
	t.Log("---------------------------")
	ptk.Dump()
}*/

func Test_TCP2(t *testing.T) {
	tpk := Newtcp()
	tpk.SrcIP = net.ParseIP("11.11.11.11")
	tpk.DstIP = net.ParseIP("11.11.22.22")
	tpk.SrcPort = 8888
	tpk.DstPort = 9999
	tpk.WndSize = 0x1234
	tpk.ACK = true
	tpk.PSH = true
	tpk.Sequence = 5802
	tpk.Acknowledgment = 5809
	tpk.Payload = []byte{0x23, 0x23}

	iphdr := ipv4.NewIPv4()
	iphdr.Version = 4
	iphdr.Identification = 0x1234
	iphdr.TTL = 64
	iphdr.Protocol = 6
	iphdr.PayLoad = tpk.ToBytes()
	iphdr.SrcIP = tpk.SrcIP
	iphdr.DstIP = tpk.DstIP

	t.Log(iphdr.ToBytes())

	/*
			iphdr.Version = 4
		iphdr.Id = 0x1234
		iphdr.SrcIP = net.ParseIP("11.11.11.11")
		iphdr.DstIP = net.ParseIP("11.11.22.22")
		iphdr.TTL = 64
		iphdr.Protocol = packet.IPProtocolTCP

		tcphdr.SrcPort = 8888
		tcphdr.DstPort = 9999
		tcphdr.Window = 0x1234
		tcphdr.ACK = true
		tcphdr.PSH = true
		tcphdr.Seq = 5802
		tcphdr.Ack = 5809
		tcphdr.Payload = []byte{0x23, 0x23}*/

}
