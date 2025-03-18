package logger

import (
	"bytes"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogger_New(t *testing.T) {
	t.Run("should create a logger", func(t *testing.T) {
		expectedLogger := &Logger{
			logger: log.Default(),
		}

		newLogger := New()
		assert.Equal(t, expectedLogger, newLogger)
	})
}

func TestLogger_Info(t *testing.T) {
	const infoMessage = "message"

	t.Run("should successfully log information", func(t *testing.T) {
		t.Run("without HTTP request", func(t *testing.T) {
			defaultLogger, testLogger := createLogger(t)

			var buf bytes.Buffer
			defaultLogger.SetOutput(&buf)

			testLogger.Info(nil, infoMessage)
			assert.Contains(t, buf.String(), infoMessage)
		})

		t.Run("with HTTP request", func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, httptest.DefaultRemoteAddr, nil)
			require.NoError(t, err)

			defaultLogger, testLogger := createLogger(t)

			var buf bytes.Buffer
			defaultLogger.SetOutput(&buf)

			testLogger.Info(req, infoMessage)
			assert.Contains(t, buf.String(), infoMessage)
			assert.Contains(t, buf.String(), http.MethodPost)
			assert.Contains(t, buf.String(), httptest.DefaultRemoteAddr)
		})
	})
}

func TestLogger_Error(t *testing.T) {
	testError := errors.New("error example")

	t.Run("should successfully log information", func(t *testing.T) {
		t.Run("without HTTP request", func(t *testing.T) {
			defaultLogger, testLogger := createLogger(t)

			var buf bytes.Buffer
			defaultLogger.SetOutput(&buf)

			testLogger.Error(nil, testError)
			assert.Contains(t, buf.String(), testError.Error())
		})

		t.Run("with HTTP request", func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, httptest.DefaultRemoteAddr, nil)
			require.NoError(t, err)

			defaultLogger, testLogger := createLogger(t)

			var buf bytes.Buffer
			defaultLogger.SetOutput(&buf)

			testLogger.Error(req, testError)
			assert.Contains(t, buf.String(), testError.Error())
			assert.Contains(t, buf.String(), http.MethodPost)
			assert.Contains(t, buf.String(), httptest.DefaultRemoteAddr)
		})
	})
}

func createLogger(t *testing.T) (*log.Logger, Logger) {
	t.Helper()

	defaultLogger := log.Default()
	testLogger := Logger{
		logger: defaultLogger,
	}

	return defaultLogger, testLogger
}
