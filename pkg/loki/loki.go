package loki

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const (
	Error = "error"
	Info  = "info"
)

// Loki holds data to configure a Loki client.
type Loki struct {
	service string
	host    string
	token   string
}

// New is a Loki client configs constructor.
func New(host, token, service string) *Loki {
	return &Loki{
		host:    host,
		token:   token,
		service: service,
	}
}

// Streams defines the Loki structure with one or many Streams of logs.
type Streams struct {
	Streams []Stream `json:"streams"`
}

// Stream defines one Stream that groups many logs, for a given application.
type Stream struct {
	Stream map[string]string `json:"stream"`
	Values [][]interface{}   `json:"values"`
}

// Value defines a Loki log values.
type Value struct {
	Timestamp string `json:"ts"`
	Line      string `json:"line"`
}

func (l *Loki) Error(r *http.Request, err error) {
	if r != nil {
		_ = l.Push(Info, fmt.Sprintf(`%s, with request data %s - %s %s`, err.Error(), r.URL.String(), r.Method, r.RemoteAddr))

		return
	}

	_ = l.Push(Error, err.Error())
}

func (l *Loki) Info(r *http.Request, message string) {
	if r != nil {
		_ = l.Push(Info, fmt.Sprintf(`%s, with request data %s - %s %s`, message, r.URL.String(), r.Method, r.RemoteAddr))

		return
	}

	_ = l.Push(Info, message)
}

// Push sends a Loki Streams posts one log to a Loki server.
func (l *Loki) Push(level, body string) error {
	value := Value{
		Timestamp: fmt.Sprintf("%d", time.Now().UnixNano()),
		Line:      body,
	}

	// Create log stream
	logStream := Stream{
		Stream: map[string]string{
			"app":   l.service,
			"level": level,
		},
		Values: [][]interface{}{
			{
				value.Timestamp,
				value.Line,
			},
		},
	}

	streams := []Stream{logStream}
	streamsPush := Streams{streams}

	// Convert to JSON
	jsonData, err := json.Marshal(streamsPush)
	if err != nil {
		return err
	}

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodPost, l.host, bytes.NewBuffer(jsonData))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+l.token) // Add auth token

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Middleware returns a middleware using Loki.
func (l *Loki) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg := fmt.Sprintf("%s - %s %s", r.URL.String(), r.Method, r.RemoteAddr)
		_ = l.Push(Info, msg)

		next.ServeHTTP(w, r)
	})
}
