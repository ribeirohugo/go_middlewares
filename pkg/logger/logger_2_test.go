package logger

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	buffer := new(bytes.Buffer)
	customLogger := log.New(buffer, "", log.LstdFlags)
	logInstance := &Logger{logger: customLogger}

	r, _ := http.NewRequest("GET", "http://example.com", nil)
	expectedMessage := "INFO: test message, with request data http://example.com - GET "
	logInstance.Info(r, "test message")

	logOutput := buffer.String()
	assert.Contains(t, logOutput, expectedMessage, "Log output does not contain expected message")
}

func TestError(t *testing.T) {
	buffer := new(bytes.Buffer)
	customLogger := log.New(buffer, "", log.LstdFlags)
	logInstance := &Logger{logger: customLogger}

	r, _ := http.NewRequest("POST", "http://example.com", nil)
	testErr := "sample error"
	expectedMessage := "ERROR: sample error, with request data http://example.com - POST "
	logInstance.Error(r, errors.New(testErr))

	logOutput := buffer.String()
	assert.Contains(t, logOutput, expectedMessage, "Log output does not contain expected message")
}

func TestMiddleware(t *testing.T) {
	buffer := new(bytes.Buffer)
	customLogger := log.New(buffer, "", log.LstdFlags)
	logInstance := &Logger{logger: customLogger}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "http://example.com/test", nil)
	req.RemoteAddr = "127.0.0.1:12345" // Ensure RemoteAddr is set
	w := httptest.NewRecorder()

	middleware := logInstance.Middleware(handler)
	middleware.ServeHTTP(w, req)

	logOutput := buffer.String()
	t.Log("Captured Log:", logOutput) // Debugging output

	assert.Contains(t, logOutput, "/test - GET", "Log output does not contain expected request data")
}
