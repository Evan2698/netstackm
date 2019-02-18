package ipv4

import (
	"bytes"
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
	fraglist *list.List
	id       uint16
	tick     int
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

	var f *fragment
	var ok bool

	f, ok = m.frag[pkg.Identification]
	if !ok {
		f = &fragment{
			fraglist: list.New(),
			tick:     MAXTICKS,
			id:       pkg.Identification,
		}
		m.frag[pkg.Identification] = f
	}

	insertfrag(pkg, f)

}

// GetHugPkg ..
func GetHugPkg(id uint16) *IPv4 {

	var payload bytes.Buffer

	f := thisfrag.getfrag(id)
	if f == nil {
		return nil
	}

	tmp := &IPv4{}
	for e := f.fraglist.Front(); e != nil; e = e.Next() {
		if one, ok := e.Value.(*IPv4); ok {
			payload.Write(one.PayLoad)
			tmp.CopyHeaderFrom(one)
		}
	}
	tmp.PayLoad = payload.Bytes()

	defer func() {
		thisfrag.delete(id)
		destoryFragment(f)
	}()
	tmp.Length = 0xff // huge flag
	return tmp
}

func insertfrag(pkg *IPv4, f *fragment) {

	var mark *list.Element
	for e := f.fraglist.Front(); e != nil; e = e.Next() {
		one, _ := e.Value.(*IPv4)
		if pkg.FragmentOffset < one.FragmentOffset {
			mark = e
			break
		}
	}
	if mark != nil {
		f.fraglist.InsertBefore(pkg, mark)

	} else {
		f.fraglist.PushBack(pkg)
	}
}

// Merge ..
func Merge(pkg *IPv4) bool {

	finish := false
	this := thisfrag.getfrag(pkg.Identification)
	if this != nil {
		finish = ((pkg.Flags & 0x1) == 0)
	}
	thisfrag.add(pkg)
	return finish
}

// destoryFragment ..
func destoryFragment(who *fragment) {
	for begin := who.fraglist.Front(); begin != nil; begin = begin.Next() {
		var pkg *IPv4
		pkg, _ = begin.Value.(*IPv4)
		if pkg != nil {
			pkg.Close()
		}
	}
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
			who := thisfrag.delete(f.id)
			if who != nil {
				destoryFragment(who)
			}
			utils.LOG.Println("ip package wait timeout:  id=", f.id)
		}
		time.Sleep(time.Minute * 1)
	}
}

func init() {
	go kd()
}
