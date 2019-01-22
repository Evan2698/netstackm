package ipv4

import "testing"

func TestOSSS(t *testing.T) {

	ipco := []byte{0x45, 0x00, 0x00, 0x34, 0x83, 0x1c, 0x40, 0x00, 0x40, 0x06, 0x57, 0x1a, 0x0a, 0x0a, 0x0a, 0x74, 0x90, 0x22, 0xbb, 0xed, 0x96, 0x78, 0x00, 0x19, 0xfd, 0x13, 0x81, 0x84, 0x7e, 0x2c, 0xe9, 0xc1, 0x80, 0x10, 0x30, 0x1f, 0x07, 0xfa, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xcc, 0xda, 0x89, 0x80, 0x2f, 0xfb, 0xda, 0xa7}
	t.Log("origin: ", ipco)
	ip := &IPv4{}
	ip.TryParseBasicHeader(ipco[:20])
	ip.TryParseBody(ipco[20:])

	t.Log("version: ", ip.Version)

	t.Log("IHL: ", ip.IHL)

	t.Log("DSCP:", ip.DSCP)

	t.Log("ECN:", ip.ECN)

	t.Log("Length:", ip.Length)

	t.Log("ID:", ip.Identification)

	t.Log("Flags:", ip.Flags)

	t.Log("FragmentOffset:", ip.FragmentOffset)

	t.Log("TTL:", ip.TTL)

	t.Log("Protocol:", ip.Protocol)

	t.Log("Sum:", ip.Sum)

	t.Log("SrcIP:", ip.SrcIP.String())
	t.Log("DstIP:", ip.DstIP.String())

	t.Log("-----------------OPTION-------------------\n")
	for i, o := range ip.Options {
		t.Log("index: ", i, "  ", o.ToBytes())
	}
	t.Log("-------------------------------------------\n")

	t.Log("payload:", ip.PayLoad)

	t.Log("------------------HSKDD-------------------\n")

	t.Log("BYTES:", ip.ToBytes())

}
