package ipv4

import (
	"bytes"
	"errors"
)

// HeaderOption ...
type HeaderOption struct {
	Copied uint8  // 1bit Set to 1 if the options need to be copied into all fragments of a fragmented packet.
	Class  uint8  // 2bits Option Class A general options category. 0 is for "control" options, and 2 is for "debugging and measurement". 1 and 3 are reserved.
	Number uint8  // 5bits Specifies an option.
	Length uint8  // Indicates the size of the entire option (including this field).
	Data   []byte // Option-specific data.
	End    bool   // user define
}

// OptionHeaderReaderWriter ..
type OptionHeaderReaderWriter interface {
	FromBytes([]byte) error
	ToBytes() []byte
	Size() uint8
	isEnd() bool
}

// Size ..
func (o *HeaderOption) Size() uint8 {
	return o.Length
}

func (o *HeaderOption) isEnd() bool {
	return o.End
}

// FromBytes ..
func (o *HeaderOption) FromBytes(op []byte) error {
	if len(op) == 0 {
		return errors.New("no options")
	}

	o.Copied = (op[0] >> 7) & 0x1
	o.Class = (op[0] >> 5) & 0x3
	o.Number = op[0] & 0x1f
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
func (o *HeaderOption) ToBytes() []byte {
	var tem uint8
	tem = o.Copied << 7
	tem = tem + (o.Class << 5)
	tem = tem + o.Number

	var outb bytes.Buffer
	outb.WriteByte(tem)
	if o.Length-1 > 0 {
		outb.WriteByte(o.Length)
		outb.Write(o.Data)
	}
	return outb.Bytes()
}

// NewOption ...
func NewOption() *HeaderOption {
	return &HeaderOption{}
}
