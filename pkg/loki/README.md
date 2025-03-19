# Loki Middleware

## Overview
Loki middleware is a logging utility designed to send HTTP request logs to a Loki server.
It provides structured logging with support for log levels and request metadata.

## Installation
Ensure you have Go modules enabled and install the package:

```sh
go get github.com/ribeirohugo/go_middlewares/pkg/loki
```

## Usage
To integrate Loki logging into your HTTP server, create a new Loki client and apply the middleware to your handlers:

```go
package main

import (
	"net/http"
	"github.com/your-repo/loki"
)

func main() {
	lokiClient := loki.New("http://loki-server-url", "your-auth-token", "your-service-name")
	http.Handle("/", lokiClient.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, World!"))
	})))

	http.ListenAndServe(":8080", nil)
}
```

## Features
- Logs request metadata (URL, method, remote address)
- Supports different log levels (`Info`, `Error`)
- Sends logs to a Loki server using HTTP requests
