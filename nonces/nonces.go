package nonces

import (
	"sync"
	"time"
)

var (
	pastNonces = map[string]bool{}
	presNonces = map[string]bool{}
	lock       = sync.RWMutex{}
)

func Add(k string) {
	lock.Lock()
	presNonces[k] = true
	lock.Unlock()
}

func Contains(k string) (v bool) {
	lock.RLock()
	if presNonces[k] || pastNonces[k] {
		v = true
	}
	lock.RUnlock()

	return
}

func init() {
	go func() {
		for {
			time.Sleep(15 * time.Second)
			lock.Lock()
			pastNonces = presNonces
			presNonces = map[string]bool{}
			lock.Unlock()
		}
	}()
}
