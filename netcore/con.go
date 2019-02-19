package netcore

import (
	"errors"
	"io"
	"net"

	"github.com/Evan2698/netstackm/common"
	"github.com/Evan2698/netstackm/ipv4"

	"github.com/Evan2698/chimney/utils"

	"time"

	"github.com/Evan2698/netstackm/tcp"
)

// Connection ...
type Connection struct {
	closed  bool
	closing bool

	Src, Dst                    net.IP
	SourcePort, DestinationPort uint16

	current *State

	Stack *Stack

	buffer []byte
	Recv   chan []byte

	input chan *tcp.TCP
}

// LocalAddr returns the local network address.
func (c *Connection) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.Src,
		Port: int(c.SourcePort),
		Zone: "",
	}
}

// RemoteAddr returns the remote network address.
func (c *Connection) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   c.Dst,
		Port: int(c.DestinationPort),
		Zone: "",
	}
}

// Read return n indicate byte numbers.
func (c *Connection) Read(b []byte) (n int, err error) {
	// clear out current buffer

	if c.closed || c.closing {
		return 0, errors.New(SocketClosed.String())
	}

	state := c.current
	if len(c.buffer) > 0 {
		state.Mutex.Lock()
		n := copy(b, c.buffer[:])
		c.buffer = c.buffer[n:]

		state.recvWindow = state.recvWindow + uint32(n)
		state.recvWindow = state.recvWindow & 0xffff
		if state.recvWindow < ipv4.MTU {
			state.recvWindow = 64420
		}
		state.Mutex.Unlock()

		return n, nil
	}

	select {
	case <-time.After(120 * time.Second):
		utils.LOG.Println("Timeout occured")
		return 0, errors.New("Timeout occured")
	case _, ok := <-c.Recv:
		if !ok {
			// connection closed?
			return 0, io.EOF
		}
		state.Mutex.Lock()
		n := copy(b[:], c.buffer[:])
		c.buffer = c.buffer[n:]

		state.recvWindow = state.recvWindow + uint32(n)
		state.recvWindow = state.recvWindow & 0xffff
		if state.recvWindow < ipv4.MTU {
			state.recvWindow = 64420
		}
		state.Mutex.Unlock()

		return n, nil
	}
}

// Write writes data to the connection.
// Write can be made to time out and return a Error with Timeout() == true
// after a fixed time limit; see SetDeadline and SetWriteDeadline.
func (c *Connection) Write(b []byte) (n int, err error) {
	if c.closed || c.closing {
		return 0, errors.New(SocketClosed.String())
	}

	state := c.current

	state.Lock()
	defer state.Unlock()

	sz := len(b)
	rest := b
	var data []byte
	standard := ipv4.MTU - 40
	for sz > 0 {
		if sz > standard {
			data = rest[:standard]
			rest = rest[standard:]
		} else {
			data = rest
			rest = nil
		}
		r := payload(state, data)
		c.Stack.sendtolow(packtcp(r), true)
		state.SendNext += uint32(len(data))
		state.sendWindow -= uint32(len(data))
		if state.sendWindow < ipv4.MTU {
			state.sendWindow = 64420
		}
		sz = len(rest)
	}

	return len(b), nil
}

// Open ...
func (c *Connection) Open(t *tcp.TCP) error {

	state := &State{
		SrcPort:  t.SrcPort,
		DestPort: t.DstPort,

		SrcIP:  t.SrcIP,
		DestIP: t.DstIP,

		Last:     time.Now(),
		RecvNext: t.Sequence + 1,
		SendNext: 1,

		sendWindow: uint32(MAX_SEND_WINDOW),
		recvWindow: uint32(MAX_RECV_WINDOW),

		Conn: c,
	}

	err := c.Stack.t.Add(t.SrcIP, t.DstIP, t.SrcPort, t.DstPort, state)
	if err != nil {
		utils.LOG.Println("can not create state ", err)
		return err
	}
	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	c.current = state
	x := synack(state)
	v := packtcp(x)
	c.Stack.sendtolow(v, false)
	c.current.SendNext = c.current.SendNext + 1
	state.SocketState = SocketSynReceived

	go c.run()

	return nil
}

func (c *Connection) run() {

	timeout := time.NewTimer(5 * time.Minute)

	for {

		timeout.Reset(5 * time.Minute)

		select {
		case t := <-c.input:
			if t.IsStop() {
				utils.LOG.Print("tcp connect exit: ", common.GenerateUniqueKey(c.Src, c.Dst, c.SourcePort, c.DestinationPort))
				timeout.Stop()
				return
			}

			utils.LOG.Println("connection: ",
				common.GenerateUniqueKey(c.Src, c.Dst, c.SourcePort, c.DestinationPort),
				"current state: ", c.current.SocketState.String())

			c.updateWindow(t)

			switch c.current.SocketState {
			case SocketSynReceived:
				c.handleSynRecived(t)
			case SocketEstablished:
				c.handleEstablished(t)
			case SocketFinWait1:
				c.handleFinWait1(t)
			case SocketFinWait2:
				c.handleFinWait2(t)
			case SocketClosing:
				c.handleClosing(t)
			case SocketLastAck:
				c.handleLastAck(t)
			default:
				utils.LOG.Println("unhandle state: ", c.current.SocketState.String())
			}

		case <-timeout.C:
			utils.LOG.Println(common.GenerateUniqueKey(c.Src, c.Dst, c.SourcePort, c.DestinationPort), "time out!!!!")
			c.notifyclose()
		}

		timeout.Stop()
	}

}
func (c *Connection) updateWindow(t *tcp.TCP) {
	state := c.current
	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	state.sendWindow = uint32(t.WndSize)
}

func (c *Connection) handleLastAck(t *tcp.TCP) {

	state := c.current
	if !validAck(state.SendNext, t.Acknowledgment) || !validSeq(t.Sequence, state.RecvNext) {
		utils.LOG.Println("valid failed in handleFinWait2")
		return
	}

	if !t.ACK {
		return
	}

	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	state.SocketState = SocketClosed
	c.notifyclose()
}

func (c *Connection) handleClosing(t *tcp.TCP) {

	state := c.current
	if !validAck(state.SendNext, t.Acknowledgment) || !validSeq(t.Sequence, state.RecvNext) {
		utils.LOG.Println("valid failed in handleFinWait2")
		return
	}

	if t.RST {
		return
	}

	if !t.ACK {
		return
	}
	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	state.SocketState = SocketTimeWait
}

func (c *Connection) handleFinWait2(t *tcp.TCP) {
	state := c.current
	if !validAck(state.SendNext, t.Acknowledgment) || !validSeq(t.Sequence, state.RecvNext) {
		utils.LOG.Println("valid failed in handleFinWait2")
		return
	}

	if t.RST {
		return
	}

	if !t.ACK || !t.FIN {
		return
	}

	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	state.RecvNext = state.RecvNext + 1
	r := ack(c.current)
	c.Stack.sendtolow(packtcp(r), true)
	state.SocketState = SocketTimeWait
}

func (c *Connection) handleFinWait1(t *tcp.TCP) {
	if !validSeq(t.Sequence, c.current.RecvNext) {
		return
	}

	// connection ends by valid RST
	if t.RST {
		return
	}
	// ignore non-ACK packets
	if !t.ACK {
		return
	}

	state := c.current
	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	if t.FIN {
		state.SendNext = state.SendNext + 1
		r := ack(c.current)
		c.Stack.sendtolow(packtcp(r), true)
		if t.ACK && validAck(state.SendNext, t.Acknowledgment) {
			state.SocketState = SocketTimeWait
			return
		}
		state.SocketState = SocketClosing
		c.closing = true
		return

	}
	state.SocketState = SocketFinWait2
}

func (c *Connection) handleEstablished(t *tcp.TCP) {

	if !validSeq(t.Sequence, c.current.RecvNext) {
		r := ack(c.current)
		c.Stack.sendtolow(packtcp(r), true)
		return
	}

	// connection ends by valid RST
	if t.RST {
		c.notifyclose()
		return
	}
	// ignore non-ACK packets
	if !t.ACK {
		r := ack(c.current)
		c.Stack.sendtolow(packtcp(r), true)
		return
	}

	state := c.current
	pl := len(t.Payload)

	if pl > 0 {
		state.Mutex.Lock()
		state.RecvNext = state.RecvNext + uint32(pl)
		state.recvWindow = state.recvWindow - uint32(pl)
		state.recvWindow = state.recvWindow & 0xffff
		if state.recvWindow < ipv4.MTU {
			state.recvWindow = 64420
		}
		state.Conn.buffer = append(state.Conn.buffer, t.Payload[:]...)
		state.Mutex.Unlock()
		select {
		case state.Conn.Recv <- []byte{}:
		default:
		}
	}
	if t.FIN {
		state.Mutex.Lock()
		state.RecvNext = state.RecvNext + 1
		r := finAck(state)
		c.Stack.sendtolow(packtcp(r), true)
		state.SocketState = SocketLastAck
		state.Mutex.Unlock()
	}
}

func (c *Connection) handleSynRecived(t *tcp.TCP) {
	state := c.current
	if !validAck(state.SendNext, t.Acknowledgment) || !validSeq(t.Sequence, state.RecvNext) {
		utils.LOG.Println("valid failed")
		if !t.RST {
			r := rst(t.SrcIP, t.DstIP, t.SrcPort, t.DstPort, t.Sequence, t.Acknowledgment, uint32(len(t.Payload)))
			c.Stack.sendtolow(packtcp(r), true)
		}
		return
	}

	if t.RST {
		c.notifyclose()
		return
	}

	if !t.ACK {
		utils.LOG.Println("ignore this packet")
		t.Dump()
		return
	}

	pl := len(t.Payload)
	state.Mutex.Lock()
	state.SocketState = SocketEstablished
	state.Mutex.Unlock()
	c.Stack.a <- c
	if pl > 0 {
		state.Mutex.Lock()
		state.RecvNext = state.RecvNext + uint32(pl)
		state.recvWindow = state.recvWindow - uint32(pl)
		state.recvWindow = state.recvWindow & 0xffff
		if state.recvWindow < ipv4.MTU {
			state.recvWindow = 64420
		}
		state.Conn.buffer = append(state.Conn.buffer, t.Payload[:]...)
		state.Mutex.Unlock()
		select {
		case state.Conn.Recv <- []byte{}:
		default:
		}
	}
}

func (c *Connection) notifyclose() {
	c.closed = true
	utils.LOG.Println("notify close action!!!")
	c.Stack.t.Remove(c.Src, c.Dst, c.SourcePort, c.DestinationPort)
}

func (c *Connection) dispatch(t *tcp.TCP) {
	c.input <- t
}

//Close ...
func (c *Connection) Close() {
	state := c.current
	state.Mutex.Lock()
	defer state.Mutex.Unlock()
	t := tcp.Newtcp()
	c.input <- t
	t.Stop = true
	c.notifyclose()
	time.Sleep(2 * time.Second)
	close(c.input)
	close(c.Recv)
	c.buffer = nil
	c.Stack = nil
	c.input = nil
	c.Recv = nil
}

// NewConnection ..
func NewConnection(src, dst net.IP, sport, dport uint16, s *Stack) *Connection {

	v := &Connection{
		Src:             src,
		Dst:             dst,
		SourcePort:      sport,
		DestinationPort: dport,
		Stack:           s,
		Recv:            make(chan []byte),
		input:           make(chan *tcp.TCP, 50),
	}
	return v
}
