package netcore

import (
	"net"
	"sync"

	"github.com/Evan2698/chimney/utils"

	"github.com/Evan2698/netstackm/common"
)

// StateTable ..
type StateTable struct {
	table map[string]*State
	lock  sync.RWMutex
}

// Add ...
func (table *StateTable) Add(src, dst net.IP, sport, dport uint16, state *State) error {
	key := common.GenerateUniqueKey(src, dst, sport, dport)
	utils.LOG.Println("add one:", key)
	table.lock.Lock()
	defer table.lock.Unlock()
	table.table[key] = state
	return nil
}

// Get ...
func (table *StateTable) Get(src, dst net.IP, sport, dport uint16) *State {
	key := common.GenerateUniqueKey(src, dst, sport, dport)
	utils.LOG.Println("Get one:", key)
	table.lock.RLock()
	defer table.lock.RUnlock()
	v, ok := table.table[key]
	if !ok {
		utils.LOG.Println("Get one:", key)
		return nil
	}

	return v
}

// Remove ...
func (table *StateTable) Remove(src, dst net.IP, sport, dport uint16) *State {
	key := common.GenerateUniqueKey(src, dst, sport, dport)
	utils.LOG.Println("Get one:", key)

	value := table.Get(src, dst, sport, dport)

	if value != nil {
		table.lock.Lock()
		defer table.lock.Unlock()
		delete(table.table, key)
	}

	return value
}

// ClearAll ...
func (table *StateTable) ClearAll() {
	table.lock.Lock()
	defer table.lock.Unlock()

	for _, v := range table.table {
		if v.Conn != nil {
			v.Conn.Close()
		}
		if v.Connu != nil {
			v.Connu.Close()
		}
	}
	table.table = nil
}
