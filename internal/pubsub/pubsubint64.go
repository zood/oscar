package pubsub

import (
	"log"
	"sync"
)

// Int64 is a hub for sending and receiving messages on different topics
type Int64 struct {
	topicChans map[int64][]chan []byte
	mutex      sync.RWMutex
}

// Pub broadcasts msg to channels subscribed to topic
func (ps *Int64) Pub(msg []byte, topic int64) {
	if msg == nil {
		return
	}

	ps.mutex.RLock()
	defer ps.mutex.RUnlock()

	for _, sub := range ps.topicChans[topic] {
		// if the channel is already full, skip it
		if len(sub) == cap(sub) {
			continue
		}
		go func(s chan []byte) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Recovered a panic during pub(): %v", r)
				}
			}()
			s <- msg
		}(sub)
	}
}

// Sub returns a channel that receives messages for topic
func (ps *Int64) Sub(topic int64) chan []byte {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	s := make(chan []byte, 5)
	subs := ps.topicChans[topic]
	subs = append(subs, s)
	ps.topicChans[topic] = subs

	return s
}

// Unsub removes the subscription c from topic
func (ps *Int64) Unsub(c chan []byte, topic int64) {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	subs := ps.topicChans[topic]
	if subs == nil {
		return
	}
	for i, sub := range subs {
		if sub == c {
			copy(subs[i:], subs[i+1:])
			subs[len(subs)-1] = nil
			subs = subs[:len(subs)-1]
			ps.topicChans[topic] = subs
			return
		}
	}
}

// NewInt64 returns an initialized Int64 key pubsub object
func NewInt64() *Int64 {
	ps := &Int64{topicChans: make(map[int64][]chan []byte)}
	return ps
}
