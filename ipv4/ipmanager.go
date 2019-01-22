package ipv4

import (
	"container/list"
	"sync"
	"time"

	"github.com/Evan2698/chimney/utils"
)

const (
	// MAXTICKS ...
	MAXTICKS = 10
)

type fragment struct {
	payload *IPv4
	tick    int
}

type fragmap struct {
	lock sync.Mutex
	frag map[uint16]*fragment
}

var (
	thisfrag = &fragmap{
		frag: make(map[uint16]*fragment),
	}
)

func (m *fragmap) getfrag(id uint16) *fragment {
	m.lock.Lock()
	defer m.lock.Unlock()
	exist, ok := m.frag[id]
	if ok {
		return exist
	}
	return nil
}

func (m *fragmap) delete(id uint16) *fragment {
	m.lock.Lock()
	defer m.lock.Unlock()
	exist, ok := m.frag[id]
	if ok {
		delete(m.frag, id)
	}
	return exist
}

func (m *fragmap) add(pkg *IPv4) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.frag[pkg.Identification] = &fragment{
		payload: pkg,
		tick:    MAXTICKS,
	}
}

// Merge ..
func Merge(pkg *IPv4) bool {

	finish := false
	this := thisfrag.getfrag(pkg.Identification)
	if this != nil {
		finish = ((pkg.Flags & 0x1) == 0)
		this.payload.PayLoad = append(this.payload.PayLoad, pkg.PayLoad...)
		this.payload.CopyHeaderFrom(pkg)
	} else {
		thisfrag.add(pkg)
	}

	return finish
}

func kd() {

	for {
		l := list.New()
		thisfrag.lock.Lock()
		for _, item := range thisfrag.frag {
			item.tick--
			if item.tick == 0 {
				l.PushBack(item)
			}
		}
		thisfrag.lock.Unlock()

		for e := l.Front(); e != nil; e = e.Next() {
			var f *fragment
			f, _ = e.Value.(*fragment)
			who := thisfrag.delete(f.payload.Identification)
			if who != nil {
				who.payload.Close()
			}
			utils.LOG.Println("ip package wait timeout:  id=", f.payload.Identification)
		}
		time.Sleep(time.Minute * 1)
	}
}

func init() {
	go kd()
}
