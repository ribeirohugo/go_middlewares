package logger

import (
	"log"
	"net/http"
)

// Logger is a struct that holds required logging dependencies.
type Logger struct {
	logger *log.Logger
}

// New is a Logger constructor.
func New() *Logger {
	return &Logger{
		logger: log.Default(),
	}
}

// Info logs a given information message.
func (l *Logger) Info(r *http.Request, message string) {
	if r != nil {
		l.logger.Printf(`INFO: %s, with request data %s - %s %s`, message, r.URL.String(), r.Method, r.RemoteAddr)

		return
	}

	l.logger.Printf(`INFO: %s`, message)
}

// Error logs a given error.
func (l *Logger) Error(r *http.Request, err error) {
	if r != nil {
		l.logger.Printf(`ERROR: %s, with request data %s - %s %s`, err.Error(), r.URL.String(), r.Method, r.RemoteAddr)

		return
	}

	l.logger.Printf(`ERROR: %s`, err.Error())
}

// Middleware is responsible for logging HTTP requests data.
// It is a middleware function, which will be called for each request.
func (l *Logger) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		l.logger.Printf("%s - %s %s", r.URL.String(), r.Method, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}
