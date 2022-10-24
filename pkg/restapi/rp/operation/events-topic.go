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
	// Data defines message(required).
	Data eventData `json:"data"`
}

type eventData struct {
	TXID string `json:"txID"`
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
	if err := json.Unmarshal(msg, d); err != nil {
		fmt.Fprintf(w, `{"error":"failed unmarshal event, cause: %s"}`, err)
	}

	if e.topics[d.Data.TXID] == nil {
		e.topics[d.Data.TXID] = make(chan []byte, topicsSize)
	}

	e.topics[d.Data.TXID] <- msg
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
