package tcp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"

	"github.com/Evan2698/chimney/utils"

	"github.com/Evan2698/tun2socks/common"
	"github.com/Evan2698/tun2socks/ipv4"
)

// TCP ..
type TCP struct {
	SrcPort        uint16 //Source port
	DstPort        uint16 // Destination port
	Sequence       uint32 //Sequence number
	Acknowledgment uint32 // Acknowledgment number (if ACK set)

	Offset   uint8 // Data offset  4bits
	Reserved uint8 // Reserved 3 bits
	NS       bool  // N	S

	CWR bool // CWR
	ECE bool // ECE
	URG bool
	ACK bool
	PSH bool
	RST bool
	SYN bool
	FIN bool

	WndSize uint16 // windows size
	Sum     uint16 // check sum
	Urgent  uint16 // Urgent pointer (if URG set)

	Options []*TCPOption

	Payload []byte // payload

	SrcIP net.IP //
	DstIP net.IP

	Stop bool
}

// TryParse ...
func (t *TCP) TryParse(b []byte) error {

	t.SrcPort = binary.BigEndian.Uint16(b[0:2])
	t.DstPort = binary.BigEndian.Uint16(b[2:4])
	t.Sequence = binary.BigEndian.Uint32(b[4:8])
	t.Acknowledgment = binary.BigEndian.Uint32(b[8:12])

	t.Offset = (b[12] >> 4) & 0xf
	t.Reserved = 0
	t.NS = (b[12] & 0x01) != 0

	t.CWR = (b[13] & 0x80) != 0
	t.ECE = (b[13] & 0x40) != 0
	t.URG = (b[13] & 0x20) != 0
	t.ACK = (b[13] & 0x10) != 0
	t.PSH = (b[13] & 0x08) != 0
	t.RST = (b[13] & 0x04) != 0
	t.SYN = (b[13] & 0x02) != 0
	t.FIN = (b[13] & 0x01) != 0

	t.WndSize = binary.BigEndian.Uint16(b[14:16])
	t.Sum = binary.BigEndian.Uint16(b[16:18])
	t.Urgent = binary.BigEndian.Uint16(b[18:20])

	if t.Offset < 5 {
		return errors.New("Invalid TCP data offset %d < 5")
	}

	headlen := (int(t.Offset)) * 4
	if headlen > len(b) {
		return errors.New("TCP data offset greater than packet length")
	}

	if headlen > 20 {
		if t.Options == nil {
			t.Options = make([]*TCPOption, 0, 4)
		}

		// have options
		opt := b[20:headlen]
		for len(opt) > 0 {
			item := &TCPOption{}
			err := item.FromBytes(opt)
			if err != nil {
				return err
			}
			opt = opt[item.Size():]
			t.Options = append(t.Options, item)

			if item.isEnd() {
				break
			}
		}
	}

	t.Payload = b[headlen:]

	return nil
}

// caloptionlength ..
func (t *TCP) caloptionlength() uint8 {

	var sz uint8

	for i := 0; i < len(t.Options); i++ {
		sz = sz + t.Options[i].Size()
	}
	if sz > 0 {
		l := sz / 4
		if (sz % 4) != 0 {
			l = l + 1
		}
		sz = l
	}
	return sz
}

// ToBytes ..
func (t *TCP) ToBytes() []byte {

	t.Offset = 5 + t.caloptionlength()

	var out bytes.Buffer
	tp := make([]byte, 4)

	binary.BigEndian.PutUint16(tp, t.SrcPort)
	out.Write(tp[:2])

	binary.BigEndian.PutUint16(tp, t.DstPort)
	out.Write(tp[:2])

	binary.BigEndian.PutUint32(tp, t.Sequence)
	out.Write(tp)

	binary.BigEndian.PutUint32(tp, t.Acknowledgment)
	out.Write(tp)

	tmp := t.Offset << 4
	if t.NS {
		tmp = tmp + 1
	}
	out.WriteByte(tmp)

	tmp = 0
	if t.CWR {
		tmp = tmp | 0x80
	}
	if t.ECE {
		tmp = tmp | 0x40
	}

	if t.URG {
		tmp = tmp | 0x20
	}

	if t.ACK {
		tmp = tmp | 0x10
	}

	if t.PSH {
		tmp = tmp | 0x08
	}

	if t.RST {
		tmp = tmp | 0x04
	}

	if t.SYN {
		tmp = tmp | 0x02
	}

	if t.FIN {
		tmp = tmp | 0x01
	}
	out.WriteByte(tmp)

	binary.BigEndian.PutUint16(tp, t.WndSize)
	out.Write(tp[:2])

	// 16.17
	out.Write([]byte{0, 0}) // checksum

	// 18. 19
	binary.BigEndian.PutUint16(tp, t.Urgent)
	out.Write(tp[:2])

	for _, k := range t.Options {
		out.Write(k.ToBytes())
	}

	// write padding
	of := (int(t.Offset) * 4) - len(out.Bytes())
	for i := 0; i < of; i++ {
		out.WriteByte(0)
	}

	header := out.Bytes()
	t.Sum = common.CalculateSum(header)
	binary.BigEndian.PutUint16(header[16:], t.Sum)

	var outX bytes.Buffer
	outX.Write(header)
	outX.Write(t.Payload)

	return outX.Bytes()

}

// CopyHeaderFrom ..
func (t *TCP) CopyHeaderFrom(tcp *TCP) {
	t.SrcPort = tcp.SrcPort
	t.DstPort = tcp.DstPort
	t.Sequence = tcp.Sequence
	t.Acknowledgment = tcp.Acknowledgment
	t.Offset = tcp.Offset
	t.Reserved = 0
	t.NS = tcp.NS

	t.CWR = tcp.CWR
	t.ECE = tcp.ECE
	t.URG = tcp.URG
	t.ACK = tcp.ACK
	t.PSH = tcp.PSH
	t.RST = tcp.RST
	t.SYN = tcp.SYN
	t.FIN = tcp.FIN

	t.WndSize = tcp.WndSize
	t.Sum = tcp.Sum
	t.Urgent = tcp.Urgent
	t.Options = tcp.Options
}

func newtcp() *TCP {
	return &TCP{}
}

// ParseTCP ..
func ParseTCP(ippkg *ipv4.IPv4) (*TCP, error) {

	tcp := newtcp()
	err := tcp.TryParse(ippkg.PayLoad)
	if err != nil {
		utils.LOG.Print("parse tcp failed: ", err)
		return nil, err
	}
	tcp.SrcIP = ippkg.SrcIP
	tcp.DstIP = ippkg.DstIP
	return tcp, nil
}

// IsStop ..
func (t *TCP) IsStop() bool {
	return t.Stop
}
