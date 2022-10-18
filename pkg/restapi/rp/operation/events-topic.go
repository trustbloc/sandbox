package operation

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

const (
	topicsSize   = 5000
	topicTimeout = 1000 * time.Millisecond
)

// EventsTopic event topic.
type EventsTopic struct {
	topics chan []byte
}

// NewEventsTopic return new event topic.
func NewEventsTopic() *EventsTopic {
	return &EventsTopic{
		topics: make(chan []byte, topicsSize),
	}
}

func (e *EventsTopic) receiveTopics(w http.ResponseWriter, r *http.Request) {
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	logger.Infof("received topic message: %s", string(msg))

	e.topics <- msg
}

func (e *EventsTopic) checkTopics(w http.ResponseWriter, r *http.Request) {
	select {
	case topic := <-e.topics:
		_, err := w.Write(topic)
		if err != nil {
			fmt.Fprintf(w, `{"error":"failed to pull topics, cause: %s"}`, err)
		}
	case <-time.After(topicTimeout):
		fmt.Fprintf(w, `{"error":"no topic found in queue"}`)
	}
}
