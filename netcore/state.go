package netcore

import (
	"net"
	"sync"
	"time"
)

const (
	MAX_RECV_WINDOW int = 65535
	MAX_SEND_WINDOW int = 65535
)

type State struct {
	sync.Mutex

	SrcIP    net.IP
	SrcPort  uint16
	DestIP   net.IP
	DestPort uint16

	Last time.Time

	RecvNext           uint32
	SendNext           uint32
	SendUnAcknowledged uint32
	LastAcked          uint32

	// flow control
	recvWindow uint32
	sendWindow uint32

	SocketState SocketState

	Connu *UDPConnection

	Conn *Connection
}
