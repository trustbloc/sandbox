package operation

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	topicsSize   = 10
	topicTimeout = 1000 * time.Millisecond
)

type event struct {
	// TransactionID defines transaction ID(optional).
	TransactionID string `json:"txnid,omitempty"`
}

// EventsTopic event topic.
type EventsTopic struct {
	topics map[string]chan []byte
}

// NewEventsTopic return new event topic.
func NewEventsTopic() *EventsTopic {
	return &EventsTopic{
		topics: make(map[string]chan []byte),
	}
}

func (e *EventsTopic) receiveTopics(w http.ResponseWriter, r *http.Request) {
	msg, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
	}

	logger.Infof("received topic message: %s", string(msg))

	d := &event{}
	if err = json.Unmarshal(msg, d); err != nil {
		fmt.Fprintf(w, `{"error":"failed unmarshal event, cause: %s"}`, err)
	}

	if e.topics[d.TransactionID] == nil {
		e.topics[d.TransactionID] = make(chan []byte, topicsSize)
	}

	e.topics[d.TransactionID] <- msg
}

func (e *EventsTopic) checkTopics(w http.ResponseWriter, r *http.Request) {
	if e.topics[r.URL.Query().Get("tx")] == nil {
		return
	}

	select {
	case topic := <-e.topics[r.URL.Query().Get("tx")]:
		_, err := w.Write(topic)
		if err != nil {
			fmt.Fprintf(w, `{"error":"failed to pull topics, cause: %s"}`, err)
		}
	case <-time.After(topicTimeout):
		fmt.Fprintf(w, `{"error":"no topic found in queue"}`)
	}
}
