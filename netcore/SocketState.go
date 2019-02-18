package netcore

import "fmt"

type SocketState int

const (
	SocketClosed SocketState = iota
	SocketListen
	SocketSynReceived
	SocketSynSent
	SocketEstablished
	SocketFinWait1
	SocketFinWait2
	SocketClosing
	SocketTimeWait
	SocketCloseWait
	SocketLastAck
)

func (ss SocketState) String() string {
	switch ss {
	case SocketClosed:
		return "SocketClosed"
	case SocketListen:
		return "SocketListen"
	case SocketSynReceived:
		return "SocketSynReceived"
	case SocketSynSent:
		return "SocketSynSent"
	case SocketEstablished:
		return "SocketEstablished"
	case SocketFinWait1:
		return "SocketFinWait1"
	case SocketFinWait2:
		return "SocketFinWait2"
	case SocketClosing:
		return "SocketClosing"
	case SocketTimeWait:
		return "SocketTimeWait"
	case SocketCloseWait:
		return "SocketCloseWait"
	case SocketLastAck:
		return "SocketLastAck"
	default:
		return fmt.Sprintf("Unknown state: %d", int(ss))
	}
}
