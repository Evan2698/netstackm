package tcp

import (
	"testing"

	"github.com/Evan2698/netstackm/ipv4"
)

func Test_TCP(t *testing.T) {

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
}
