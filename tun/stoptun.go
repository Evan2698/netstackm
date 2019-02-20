package tun

import (
	"errors"
	"io"
)

// ReadWriteCloseStoper ..
type ReadWriteCloseStoper interface {
	io.ReadWriteCloser
	SetStop(stop bool)
}

type tunstoper struct {
	f    io.ReadWriteCloser
	stop bool
}

func (t *tunstoper) Read(p []byte) (n int, err error) {
	if t.stop {
		return 0, errors.New("stop")
	}

	n, err = t.f.Read(p)

	if t.stop {
		return 0, errors.New("stop")
	}

	return n, err
}

func (t *tunstoper) Write(p []byte) (n int, err error) {
	if t.stop {
		return 0, errors.New("stop")
	}

	n, err = t.f.Write(p)

	if t.stop {
		return 0, errors.New("stop")
	}

	return n, err
}

func (t *tunstoper) Close() error {
	err := t.f.Close()
	if t.stop {
		return errors.New("stop")
	}
	return err
}

func (t *tunstoper) SetStop(stop bool) {
	t.stop = stop
}

// NewTunDevice ..
func NewTunDevice(k io.ReadWriteCloser) ReadWriteCloseStoper {

	return &tunstoper{
		f:    k,
		stop: false,
	}
}
