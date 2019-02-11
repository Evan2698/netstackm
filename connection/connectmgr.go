package connection

import (
	"sync"
)

type conectmgr struct {
	lock sync.Mutex
	mgr  map[string]netConnectImp
}

func (c *conectmgr) getconnect(key string) netConnectImp {
	c.lock.Lock()
	defer c.lock.Unlock()

	con, ok := c.mgr[key]
	if ok {
		return con
	}
	return nil
}

func (c *conectmgr) push(key string, con netConnectImp) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.mgr[key] = con
}

func (c *conectmgr) delete(key string) netConnectImp {
	c.lock.Lock()
	defer c.lock.Unlock()
	exist, ok := c.mgr[key]
	if ok {
		delete(c.mgr, key)
	}
	return exist
}

func (c *conectmgr) removeall() {
	c.lock.Lock()
	defer c.lock.Unlock()
	for _, v := range c.mgr {
		v.Close()
	}
	c.mgr = nil
}
