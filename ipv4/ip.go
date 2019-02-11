package ipv4

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync/atomic"

	"github.com/Evan2698/chimney/utils"

	"github.com/Evan2698/tun2socks/common"
)

var (
	//MTU  package size
	MTU = 1500
)

// IPv4 ..
type IPv4 struct {
	Version        uint8           // Version 4bits
	IHL            uint8           // Internet Header Length  4bits
	DSCP           uint8           // Differentiated Services Code Point  6bits
	ECN            uint8           // Explicit Congestion Notification 2bits
	Length         uint16          // Total length   16bits
	Identification uint16          // Identification 16 bits
	Flags          uint8           // Flags 3 bits
	FragmentOffset uint16          // Fragment Offset 13 bits
	TTL            uint8           // Time to Live 8 bits
	Protocol       uint8           // protocol  8bits
	Sum            uint16          // Header Checksum
	SrcIP          net.IP          // source ip address 4 bytes
	DstIP          net.IP          // destination ip address 4 bytes
	Options        []*HeaderOption // header options
	PayLoad        []byte          // playload
}

// IPv4ReaderWriter ..
type IPv4ReaderWriter interface {
	TryParseBasicHeader([]byte) error
	TryParseBody([]byte) error
	ToBytes() []byte
	Close()
	IsStop() bool
}

// TryParseBasicHeader ..
func (ip *IPv4) TryParseBasicHeader(co []byte) error {
	if len(co) < 20 {
		return errors.New("ip package is incorrect")
	}

	ip.Version = (co[0] >> 4) & 0xf
	ip.IHL = co[0] & 0xf

	ip.DSCP = (co[1] >> 2) & 0x3f
	ip.ECN = co[1] & 0x3

	ip.Length = (uint16(co[2]) << 8) + uint16(co[3])

	ip.Identification = (uint16(co[4]) << 8) + uint16(co[5])

	ip.Flags = (co[6] >> 5) & 0x7
	ip.FragmentOffset = ((uint16(co[6]) & 0x3f) << 8) + uint16(co[7])

	ip.TTL = co[8]

	ip.Protocol = co[9]

	ip.Sum = (uint16(co[10]) << 8) + uint16(co[11])

	ip.SrcIP = net.IP(co[12:16])
	ip.DstIP = net.IP(co[16:20])

	if ip.Length < 20 {
		return errors.New("Invalid (too small) IP length  < 20")
	}
	if ip.IHL < 5 {
		return errors.New("Invalid (too small) IP header length (IHL < 5)")
	}
	if int(ip.IHL*4) > int(ip.Length) {
		return errors.New("Invalid IP header length > IP length")
	}
	return nil
}

// TryParseBody ...
func (ip *IPv4) TryParseBody(co []byte) error {
	if ip.IHL*4 > 20 {
		if ip.Options == nil {
			ip.Options = make([]*HeaderOption, 0, 4)
		}

		// have options
		opt := co[0:(ip.IHL*4 - 20)]
		for len(opt) > 0 {
			item := NewOption()
			err := item.FromBytes(opt)
			if err != nil {
				return err
			}
			opt = opt[item.Size():]
			ip.Options = append(ip.Options, item)

			if item.isEnd() {
				break
			}
		}
	}

	if len(co) < int(ip.Length-20) {
		return errors.New("Invalid ip body")
	}

	ip.PayLoad = co[ip.IHL*4-20 : ip.Length-20]

	return nil
}

func (ip *IPv4) caloptionlength() uint8 {

	var sz uint8

	for i := 0; i < len(ip.Options); i++ {
		sz = sz + ip.Options[i].Size()
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
func (ip *IPv4) ToBytes() []byte {

	ip.IHL = 5 + ip.caloptionlength()

	var con bytes.Buffer

	tmp := (ip.Version << 4) | ip.IHL
	con.WriteByte(tmp)

	tmp = (ip.DSCP << 6) | ip.ECN
	con.WriteByte(tmp)

	ip.Length = uint16(len(ip.PayLoad)) + uint16(ip.IHL*4)
	tmp = uint8((ip.Length >> 8) & 0xff)
	con.WriteByte(tmp)
	tmp = uint8(ip.Length & 0xff)
	con.WriteByte(tmp)

	tmp = uint8((ip.Identification >> 8) & 0xff)
	con.WriteByte(tmp)
	tmp = uint8(ip.Identification & 0xff)
	con.WriteByte(tmp)

	tmp = (ip.Flags << 5) | uint8(((ip.FragmentOffset >> 8) & 0x7))
	con.WriteByte(tmp)
	tmp = uint8(ip.FragmentOffset & 0xff)
	con.WriteByte(tmp)

	con.WriteByte(ip.TTL)

	con.WriteByte(ip.Protocol)

	con.Write([]byte{0, 0})
	con.Write(ip.SrcIP.To4())
	con.Write(ip.DstIP.To4())

	for i := 0; i < len(ip.Options); i++ {
		con.Write(ip.Options[i].ToBytes())
	}

	of := (int(ip.IHL) * 4) - len(con.Bytes())
	for i := 0; i < of; i++ {
		con.WriteByte(0)
	}

	hr := con.Bytes()
	ip.Sum = common.CalculateSum(hr)
	binary.BigEndian.PutUint16(hr[10:], ip.Sum)
	return append(hr, ip.PayLoad...)
}

// Close ..
func (ip *IPv4) Close() {
	ip.Options = nil
	ip.PayLoad = nil
}

// CopyHeaderFrom ..
func (ip *IPv4) CopyHeaderFrom(it *IPv4) {
	ip.Version = it.Version
	ip.IHL = it.IHL
	ip.Identification = it.Identification
	ip.DSCP = it.DSCP
	ip.ECN = it.ECN
	ip.Length = it.Length
	ip.Flags = it.Flags
	ip.FragmentOffset = it.FragmentOffset
	ip.TTL = it.TTL
	ip.Protocol = it.Protocol
	ip.Sum = it.Sum
	ip.SrcIP = it.SrcIP
	ip.DstIP = it.DstIP
	ip.Options = it.Options
}

// IsStop ..
func (ip *IPv4) IsStop() bool {
	return ip.Version == 0xff
}

// Dump ...
func Dump(ip *IPv4) {
	utils.LOG.Println("src IP: ", ip.SrcIP.To4().String())
	utils.LOG.Println("dst IP: ", ip.DstIP.To4().String())
	utils.LOG.Println("id: ", ip.Identification)
	utils.LOG.Println("Flags: ", ip.Flags)
	utils.LOG.Println("Length: ", ip.Length)
}

var globalIPID uint32

//GeneratorIPID ...
func GeneratorIPID() uint16 {
	return uint16(atomic.AddUint32(&globalIPID, 1) & 0x0000ffff)
}
