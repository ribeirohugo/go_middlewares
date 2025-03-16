# CORS Middleware Documentation

## Overview
This document describes the functionality of the CORS (Cross-Origin Resource Sharing) middleware implemented in Go. The middleware is responsible for handling CORS policies by allowing or blocking HTTP requests based on their origin.

## Features
- Allows requests from specified origins.
- Rejects requests from disallowed origins with a `403 Forbidden` response.
- Handles `OPTIONS` requests for preflight checks.
- Supports wildcard (`*`) when no allowed origins are specified.

## Usage

### Middleware Constructor
```go
c := cors.New([]string{"http://example.com", "http://another.com"})
```
This initializes the middleware with a list of allowed origins.

### Applying Middleware
```go
handler := c.Middleware(http.HandlerFunc(yourHandler))
http.Handle("/api", handler)
```
Wrap your HTTP handler with the CORS middleware before serving requests.

## Behavior

| Scenario | Expected Behavior |
|----------|------------------|
| Request from an allowed origin | `Access-Control-Allow-Origin` is set to the origin |
| Request from a disallowed origin | Responds with `403 Forbidden` |
| OPTIONS preflight request | Responds with `200 OK` and necessary headers |
| No allowed origins specified | Allows all origins (`*`) |

## Example Request Handling

### Allowed Origin
**Request:**
```
Origin: http://example.com
```
**Response Headers:**
```
Access-Control-Allow-Origin: http://example.com
```

### Disallowed Origin
**Request:**
```
Origin: http://notallowed.com
```
**Response:**
```
HTTP 403 Forbidden
```

### Wildcard Mode
When no allowed origins are configured:
**Response Headers:**
```
Access-Control-Allow-Origin: *
```

## Conclusion
This middleware ensures secure cross-origin requests while allowing flexibility in configuring allowed origins. Modify the allowed origins list based on your security needs.
