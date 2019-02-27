package netcore

import (
	"errors"
	"fmt"
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

	Recv chan bool
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
		state.lockObject.Lock()
		n := copy(b, c.buffer[:])
		c.buffer = c.buffer[n:]
		state.recvWindow = 64420
		state.lockObject.Unlock()

		return n, nil
	}

	select {
	case <-time.After(300 * time.Second):
		fmt.Println("Timeout occured")
		return 0, errors.New("Timeout occured.")
	case _, ok := <-c.Recv:
		if !ok {
			// connection closed?
			return 0, io.EOF
		}
		state.lockObject.Lock()
		n = copy(b[:], c.buffer[:])
		c.buffer = c.buffer[n:]
		state.recvWindow = 64420
		state.lockObject.Unlock()
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
	sz := len(b)
	rest := b
	var data []byte
	standard := ipv4.MTU - 40
	for sz > 0 {
		state.lockObject.Lock()
		if sz > standard {
			data = rest[:standard]
			rest = rest[standard:]
		} else {
			data = rest
			rest = nil
		}
		r := payload(state, data)
		c.Stack.SendTo(packtcp(r))
		state.SendNext += uint32(len(data))
		state.sendWindow = 64420
		sz = len(rest)
		state.lockObject.Unlock()
	}

	return len(b), nil
}

// Open ...
func (c *Connection) Open(t *tcp.TCP) error {

	sendNext := uint32(c.Stack.r.Int31n(2147483))
	state := &State{
		SrcPort:  t.SrcPort,
		DestPort: t.DstPort,

		SrcIP:  t.SrcIP,
		DestIP: t.DstIP,

		Last:     time.Now(),
		RecvNext: t.Sequence + 1,
		SendNext: sendNext,

		sendWindow: uint32(MAX_SEND_WINDOW),
		recvWindow: uint32(MAX_RECV_WINDOW),

		Conn: c,
	}

	err := c.Stack.t.Add(t.SrcIP, t.DstIP, t.SrcPort, t.DstPort, state)
	if err != nil {
		utils.LOG.Println("can not create state ", err)
		return err
	}
	state.lockObject.Lock()
	defer state.lockObject.Unlock()
	c.current = state
	x := synack(state)
	v := packtcp(x)
	c.Stack.SendTo(v)
	c.current.SendNext = c.current.SendNext + 1
	state.SocketState = SocketSynReceived
	return nil
}

func (c *Connection) run(t *tcp.TCP) {

	if t.IsStop() {
		utils.LOG.Print("tcp connect exit: ", common.GenerateUniqueKey(c.Src, c.Dst, c.SourcePort, c.DestinationPort))
		return
	}

	utils.LOG.Println("connection: ",
		common.GenerateUniqueKey(c.Src, c.Dst, c.SourcePort, c.DestinationPort),
		"current state: ", c.current.SocketState.String())

	utils.LOG.Println("================================ begin")
	t.Dump()
	c.current.Dump()
	utils.LOG.Println("================================ end !!")

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
		return
	default:
		utils.LOG.Println("unhandle state: ", c.current.SocketState.String())
	}

}
func (c *Connection) updateWindow(t *tcp.TCP) {
	state := c.current
	state.lockObject.Lock()
	defer state.lockObject.Unlock()
	state.sendWindow = uint32(t.WndSize)
}

func (c *Connection) handleLastAck(t *tcp.TCP) {

	c.handleclosed()
	state := c.current
	if !validAck(state.SendNext, t.Acknowledgment) || !validSeq(t.Sequence, state.RecvNext) {
		utils.LOG.Println("valid failed in handleFinWait2")
		return
	}

	if !t.ACK {
		return
	}

	state.lockObject.Lock()
	state.SocketState = SocketClosed
	state.lockObject.Unlock()
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
	state.lockObject.Lock()
	defer state.lockObject.Unlock()
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

	state.lockObject.Lock()
	defer state.lockObject.Unlock()
	state.RecvNext = state.RecvNext + 1
	r := ack(c.current)
	c.Stack.SendTo(packtcp(r))
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
	state.lockObject.Lock()
	defer state.lockObject.Unlock()
	if t.FIN {
		state.RecvNext = state.RecvNext + 1
		r := ack(c.current)
		c.Stack.SendTo(packtcp(r))
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
		c.Stack.SendTo(packtcp(r))
		return
	}

	// connection ends by valid RST
	if t.RST {
		utils.LOG.Print("OPPPPPSS RST")
		//c.notifyclose()
		return
	}
	// ignore non-ACK packets
	if !t.ACK {
		r := ack(c.current)
		c.Stack.SendTo(packtcp(r))
		return
	}

	state := c.current
	pl := len(t.Payload)
	state.lockObject.Lock()
	defer state.lockObject.Unlock()
	if pl > 0 {
		state.RecvNext = state.RecvNext + uint32(pl)
		state.recvWindow = 64420
		state.Conn.buffer = append(state.Conn.buffer, t.Payload[:]...)
		select {
		case c.Recv <- true:
		default:
		}
	}
	// ack
	//ak := ack(state)
	//c.Stack.sendtolow(packtcp(ak), true)
	//------------------------------

	if t.FIN {
		state.RecvNext = state.RecvNext + 1
		r := finAck(state)
		c.Stack.SendTo(packtcp(r))
		state.SendNext = state.SendNext + 1
		state.SocketState = SocketLastAck
	}
}

func (c *Connection) handleSynRecived(t *tcp.TCP) {
	state := c.current
	if !validAck(state.SendNext, t.Acknowledgment) || !validSeq(t.Sequence, state.RecvNext) {
		utils.LOG.Println("valid failed")
		if !t.RST {
			r := rst(t.SrcIP, t.DstIP, t.SrcPort, t.DstPort, t.Sequence, t.Acknowledgment, uint32(len(t.Payload)))
			c.Stack.SendTo(packtcp(r))
		}
		return
	}

	if t.RST {
		utils.LOG.Println("ignore this packet", state.SocketState.String())
		t.Dump()
		//c.notifyclose()
		return
	}

	if !t.ACK {
		utils.LOG.Println("ignore this packet")
		t.Dump()
		return
	}

	pl := len(t.Payload)

	state.lockObject.Lock()
	defer state.lockObject.Unlock()

	if pl > 0 {

		state.recvWindow = 64420
		state.Conn.buffer = append(state.Conn.buffer, t.Payload[:]...)
	}

	//ac := ack(state)
	//c.Stack.sendtolow(packtcp(ac), true)
	state.RecvNext = state.RecvNext + uint32(pl)
	state.SocketState = SocketEstablished
	c.Stack.a <- c
	select {
	case c.Recv <- true:
	default:
	}
}

func (c *Connection) handleclosed() {
	c.closed = true
	utils.LOG.Println("notify close action!!!")
	c.Stack.t.Remove(c.Src, c.Dst, c.SourcePort, c.DestinationPort)
}

func (c *Connection) notifyclose() {
	state := c.current
	state.lockObject.Lock()
	state.RecvNext = state.RecvNext + 1
	t := finAck(state)
	c.Stack.SendTo(packtcp(t))
	state.SendNext = state.SendNext + 1
	state.SocketState = SocketFinWait1
	state.lockObject.Unlock()
}

func (c *Connection) dispatch(t *tcp.TCP) {
	c.run(t)
}

//Close ...
func (c *Connection) Close() {
	utils.LOG.Print("close function was called by caller..")
	c.notifyclose()
	select {
	case c.Recv <- true:
	default:
	}
	time.Sleep(time.Second * 10)

	state := c.current
	state.lockObject.Lock()
	defer state.lockObject.Unlock()

	c.buffer = nil
	c.Stack = nil
	c.Recv = nil
	utils.LOG.Println(common.GenerateUniqueKey(c.Src, c.Dst, c.SourcePort, c.DestinationPort), "TCP connection exit!!!!!")
}

// NewConnection ..
func NewConnection(src, dst net.IP, sport, dport uint16, s *Stack) *Connection {

	v := &Connection{
		Src:             src,
		Dst:             dst,
		SourcePort:      sport,
		DestinationPort: dport,
		Stack:           s,
		Recv:            make(chan bool),
	}

	return v
}
