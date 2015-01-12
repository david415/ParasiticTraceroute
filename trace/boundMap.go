package trace

import (
	"container/ring"
	"github.com/david415/HoneyBadger"
	"sync"
)

type SequenceFlowBoundMap struct {
	lock        *sync.RWMutex
	sequenceMap map[uint32]HoneyBadger.TcpIpFlow
	ring        *ring.Ring
	head        *ring.Ring
	count       int
	max         int
}

func NewSequenceFlowBoundMap(size int) SequenceFlowBoundMap {
	ring := ring.New(size)
	return SequenceFlowBoundMap{
		max:         size,
		lock:        new(sync.RWMutex),
		sequenceMap: make(map[uint32]HoneyBadger.TcpIpFlow),
		ring:        ring,
		head:        ring,
	}
}

func (s *SequenceFlowBoundMap) Put(seq uint32, flow HoneyBadger.TcpIpFlow) {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.ring.Next()
	if s.count >= s.max {
		delete(s.sequenceMap, s.ring.Value.(uint32))
	} else {
		s.count += 1
	}
	s.ring.Value = seq
	s.sequenceMap[seq] = flow
}

func (s *SequenceFlowBoundMap) Has(seq uint32) bool {
	s.lock.RLock()
	defer s.lock.RUnlock()
	_, ok := s.sequenceMap[seq]
	return ok
}

func (s *SequenceFlowBoundMap) Get(seq uint32) HoneyBadger.TcpIpFlow {
	s.lock.RLock()
	defer s.lock.RUnlock()
	return s.sequenceMap[seq]
}

func main() {
	seqMap := NewSequenceFlowBoundMap(3)
	flow := HoneyBadger.TcpIpFlow{}
	var i uint32
	for i = 0; i < 10; i++ {
		seqMap.Put(i, flow)
	}
}
