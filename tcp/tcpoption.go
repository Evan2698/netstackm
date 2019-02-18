package tcp

import (
	"bytes"
	"errors"

	"github.com/Evan2698/chimney/utils"
)

// TCPOption ...
type TCPOption struct {
	Type   uint8
	Length uint8
	Data   []byte
	End    bool // user define
}

func (o *TCPOption) Size() uint8 {

	return o.Length
}

func (o *TCPOption) isEnd() bool {
	return o.End
}

// FromBytes ..
func (o *TCPOption) FromBytes(op []byte) error {
	if len(op) == 0 {
		return errors.New("no options")
	}
	o.Type = op[0]
	if op[0] == 0 || op[0] == 1 {
		o.Length = 1
		o.Data = nil
		o.End = (op[0] == 0)
	} else {
		o.Length = op[1]
		o.Data = op[2:o.Length]
		if len(o.Data) == 0 {
			o.Data = nil
		}
	}
	return nil
}

// ToBytes ..
func (o *TCPOption) ToBytes() []byte {

	var outb bytes.Buffer
	outb.WriteByte(o.Type)
	if o.Length-1 > 0 {
		outb.WriteByte(o.Length)
		outb.Write(o.Data)
	}
	return outb.Bytes()
}

// NewTCPOption ...
func NewTCPOption() *TCPOption {

	return &TCPOption{}
}

// Dump ...
func (o *TCPOption) Dump() {
	utils.LOG.Println("==========================")
	utils.LOG.Println("type: ", o.Type)
	utils.LOG.Println("length: ", o.Length)
	utils.LOG.Println("DATA: ", o.Data)
	utils.LOG.Println("==========================")

}
