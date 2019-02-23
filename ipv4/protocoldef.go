package ipv4

type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop    IPProtocol = 0
	IPProtocolICMPv4          IPProtocol = 1
	IPProtocolIGMP            IPProtocol = 2
	IPProtocolIPv4            IPProtocol = 4
	IPProtocolTCP             IPProtocol = 6
	IPProtocolUDP             IPProtocol = 17
	IPProtocolRUDP            IPProtocol = 27
	IPProtocolIPv6            IPProtocol = 41
	IPProtocolIPv6Routing     IPProtocol = 43
	IPProtocolIPv6Fragment    IPProtocol = 44
	IPProtocolGRE             IPProtocol = 47
	IPProtocolESP             IPProtocol = 50
	IPProtocolAH              IPProtocol = 51
	IPProtocolICMPv6          IPProtocol = 58
	IPProtocolNoNextHeader    IPProtocol = 59
	IPProtocolIPv6Destination IPProtocol = 60
	IPProtocolIPIP            IPProtocol = 94
	IPProtocolEtherIP         IPProtocol = 97
	IPProtocolSCTP            IPProtocol = 132
	IPProtocolUDPLite         IPProtocol = 136
	IPProtocolMPLSInIP        IPProtocol = 137

	IPv4_PSEUDO_LENGTH int = 12
)

func (s IPProtocol) String() string {
	switch s {
	case IPProtocolIPv6HopByHop:
		return "IPv6HopByHop"
	case IPProtocolICMPv4:
		return "ICMPv4"
	case IPProtocolIGMP:
		return "IGMP"
	case IPProtocolIPv4:
		return "IPv4"
	case IPProtocolTCP:
		return "TCP"
	case IPProtocolUDP:
		return "UDP"
	case IPProtocolRUDP:
		return "RUDP"
	case IPProtocolIPv6:
		return "IPv6"
	case IPProtocolIPv6Routing:
		return "IPv6Routing"
	case IPProtocolIPv6Fragment:
		return "IPv6Fragment"
	case IPProtocolGRE:
		return "GRE"
	case IPProtocolESP:
		return "ESP"
	case IPProtocolAH:
		return "AH"
	case IPProtocolICMPv6:
		return "ICMPv6"
	case IPProtocolNoNextHeader:
		return "NoNextHeader"
	case IPProtocolIPv6Destination:
		return "IPv6Destination"
	case IPProtocolIPIP:
		return "IPIP"
	case IPProtocolEtherIP:
		return "EtherIP"
	case IPProtocolSCTP:
		return "SCTP"
	case IPProtocolUDPLite:
		return "UDPLite"
	case IPProtocolMPLSInIP:
		return "MPLSInIP"
	}

	return "unknown"
}

const (
	MTU = 1500
)
