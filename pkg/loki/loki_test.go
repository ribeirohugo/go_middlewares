package loki

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPush(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method, "expected method POST")
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"), "expected Content-Type application/json")

		body, err := ioutil.ReadAll(r.Body)
		assert.NoError(t, err)

		var streams Streams
		assert.NoError(t, json.Unmarshal(body, &streams))
		assert.Len(t, streams.Streams, 1, "expected 1 stream")

		w.WriteHeader(http.StatusOK)
	}

	ts := httptest.NewServer(http.HandlerFunc(handler))
	defer ts.Close()

	loki := New(ts.URL, "test-token", "test-service")
	err := loki.Push(Info, "test log message")
	assert.NoError(t, err, "Push returned an error")
}

func TestError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	loki := New(ts.URL, "test-token", "test-service")
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	err := loki.Push(Error, "test error message")
	assert.NoError(t, err, "Error method failed")

	loki.Error(r, assert.AnError)
}

func TestInfo(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	loki := New(ts.URL, "test-token", "test-service")
	r, _ := http.NewRequest("GET", "http://example.com", nil)
	loki.Info(r, "test info message")
}

func TestMiddleware(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	loki := New(ts.URL, "test-token", "test-service")
	handler := loki.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://example.com", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Result().StatusCode, "expected status OK")
}
