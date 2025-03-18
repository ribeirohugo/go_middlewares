# Go Middlewares

Go Middlewares is a packages repository, developed in Golang, that aggregates standard middlewares
that are commonly used by different applications.

## 1.1. JWT Middleware

[JWT](pkg/jwt) is a middleware for handling JSON Web Tokens (JWT) to securely authenticate and authorize
HTTP and HTTPS requests, ensuring that only valid and properly signed tokens are processed for
access control and user verification.

## 1.2. CORS Middleware

[CORS](pkg/cors) is a middleware responsible for handling Cross-Origin Resource Sharing (CORS) policies
by allowing or blocking HTTP requests based on their origin.

## 1.3. Logger Middleware

[Logger](pkg/logger) is a middleware responsible for logging HTTP request data, including the request method,
URL, and remote address. It helps track incoming requests and provides useful debugging information.
