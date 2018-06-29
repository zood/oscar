package pubsub

import (
	"log"
	"sync"
)

// PubSub is a hub for sending and receiving messages on different topics
type PubSub struct {
	topicChans map[string][]chan []byte
	mutex      sync.RWMutex
}

// Pub broadcasts msg to channels subscribed to topic
func (ps *PubSub) Pub(msg []byte, topic string) {
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
func (ps *PubSub) Sub(topic string) chan []byte {
	ps.mutex.Lock()
	defer ps.mutex.Unlock()

	s := make(chan []byte, 5)
	subs := ps.topicChans[topic]
	subs = append(subs, s)
	ps.topicChans[topic] = subs

	return s
}

// Unsub removes the subscription c from topic
func (ps *PubSub) Unsub(c chan []byte, topic string) {
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

// New returns an initialized PubSub object
func New() *PubSub {
	ps := &PubSub{topicChans: make(map[string][]chan []byte)}
	return ps
}
