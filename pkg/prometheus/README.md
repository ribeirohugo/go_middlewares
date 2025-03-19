# Prometheus Middleware

This repository provides a Prometheus middleware for monitoring HTTP requests in a Go application.
The middleware captures request counts, response times, and status codes, and exposes them via a `/metrics` endpoint.

## Features
- Tracks total HTTP requests (`http_requests_total`)
- Records request duration (`http_request_duration_seconds`)
- Supports authentication for the `/metrics` endpoint
- Middleware for automatic metrics collection

## Installation

```sh
go get github.com/ribeirohugo/go_middlewares/pkg/prometheus
```

## Usage

### Initialize Middleware

```go
p := prometheus.NewPrometheus("my-service", "your-auth-token")
```

### Secure Metrics Endpoint

```go
http.HandleFunc("/metrics", p.Handler)
```

### Apply Middleware to Handlers

```go
mux := http.NewServeMux()
mux.Handle("/example", p.Middleware(http.HandlerFunc(exampleHandler)))

http.ListenAndServe(":8080", mux)
```
