package tcp

import (
	"bytes"
	"errors"
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
