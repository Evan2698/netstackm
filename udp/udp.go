package udp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strconv"

	"github.com/Evan2698/chimney/utils"
	"github.com/Evan2698/netstackm/ipv4"

	"github.com/Evan2698/netstackm/common"
)

// UDP ...
type UDP struct {
	SrcPort      uint16
	DstPort      uint16
	Length       uint16
	Checksum     uint16
	Payload      []byte
	Stop         bool
	SrcIP, DstIP net.IP
}

// TryParse ..
func TryParse(ip *ipv4.IPv4) (*UDP, error) {
	t := NewUDP()
	b := ip.PayLoad

	if len(b) < 8 {
		return nil, errors.New("payload too small for UDP:" + strconv.Itoa(len(b)) + " bytes")
	}

	t.SrcPort = binary.BigEndian.Uint16(b[0:2])
	t.DstPort = binary.BigEndian.Uint16(b[2:4])
	t.Length = binary.BigEndian.Uint16(b[4:6])
	t.Checksum = binary.BigEndian.Uint16(b[6:8])
	if len(b) > 8 {
		t.Payload = b[8:]
	} else {
		t.Payload = nil
	}

	t.SrcIP = ip.SrcIP
	t.DstIP = ip.DstIP

	return t, nil
}

// ToBytes ..
func (t *UDP) ToBytes() []byte {
	tmp := make([]byte, 2)
	var out bytes.Buffer

	binary.BigEndian.PutUint16(tmp, t.SrcPort)
	out.Write(tmp)

	binary.BigEndian.PutUint16(tmp, t.DstPort)
	out.Write(tmp)

	t.Length = uint16(len(t.Payload)) + 8
	binary.BigEndian.PutUint16(tmp, t.Length)
	out.Write(tmp)

	out.Write([]byte{0, 0})

	out.Write(t.Payload)
	co := out.Bytes()

	t.Checksum = common.CalculateSum(t.buildchecksumcontent(t.SrcIP, t.DstIP, co))

	binary.BigEndian.PutUint16(co[6:], t.Checksum)

	return co

}

func (t *UDP) buildchecksumcontent(src, dst net.IP, co []byte) []byte {
	var out bytes.Buffer

	out.Write(t.buildPseudoHeader(src, dst))
	out.Write(co)
	return out.Bytes()
}

func (t *UDP) buildPseudoHeader(src, dst net.IP) []byte {
	var out bytes.Buffer
	out.Write(src.To4())
	out.Write(dst.To4())
	out.WriteByte(0x00)
	out.WriteByte(uint8(ipv4.UDP))
	out.WriteByte(uint8(t.Length >> 8))
	out.WriteByte(uint8(t.Length & 0xff))
	return out.Bytes()
}

// IsStop ...
func (t *UDP) IsStop() bool {
	return t.Stop
}

// NewUDP ..
func NewUDP() *UDP {
	return &UDP{}
}

// Dump ..
func (t *UDP) Dump() {
	utils.LOG.Println("----------------UDP---------------")
	utils.LOG.Println("src", t.SrcIP.String(), ":", t.SrcPort, "<->", t.DstIP.String(), ":", t.DstPort)
	utils.LOG.Println("----------------UDP---------------")
}
