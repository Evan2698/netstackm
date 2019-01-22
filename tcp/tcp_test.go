package tcp

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestOPS(t *testing.T) {

	tcp := []byte{0x96, 0x78, 0x00, 0x19, 0xfd, 0x13, 0x81, 0x84, 0x7e, 0x2c, 0xe9, 0xc1, 0x80, 0x10, 0x30, 0x1f, 0x07, 0xfa, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xcc, 0xda, 0x89, 0x80, 0x2f, 0xfb, 0xda, 0xa7, 0x45, 0x54}

	t.Log(tcp)
	ts := newtcp()
	ts.TryParse(tcp)
	t.Log("SRC: ", ts.SrcPort)
	t.Log("DST: ", ts.DstPort)

	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, ts.Sequence)

	t.Log("SEQ: ", ts.Sequence, hex.EncodeToString(b))

	binary.BigEndian.PutUint32(b, ts.Acknowledgment)
	t.Log("ack: ", ts.Acknowledgment, hex.EncodeToString(b))

	t.Log("OFFSET: ", ts.Offset)
	t.Log("NS: ", ts.NS)
	t.Log("CWR: ", ts.CWR)
	t.Log("ECE: ", ts.ECE)
	t.Log("URG: ", ts.URG)
	t.Log("ACK: ", ts.ACK)
	t.Log("PSH: ", ts.PSH)
	t.Log("RST: ", ts.RST)
	t.Log("SYN: ", ts.SYN)
	t.Log("FIN: ", ts.FIN)

	t.Log("WND: ", ts.WndSize)
	t.Log("SUM:", ts.Sum)
	t.Log("urgent", ts.Urgent)

	t.Log("-----------------OPTION-------------------\n")
	for i, o := range ts.Options {
		t.Log("index: ", i, "  ", o.ToBytes())
	}
	t.Log("-------------------------------------------\n")

	t.Log("payload: ", ts.Payload)

	t.Log(ts.ToBytes())

}
