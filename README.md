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

## 1.4. Prometheus Middleware

[Prometheus](pkg/prometheus) is a middleware designed for monitoring HTTP requests by collecting key metrics
such as request count, response duration, and status codes.
It enables seamless integration with Prometheus for real-time performance tracking and observability.

## 1.5. Loki Middleware

[Loki](pkg/loki) is a middleware responsible for logging HTTP request data to a Loki server.
It captures essential request details such as the request method, URL, and remote address, ensuring structured
logging for better observability and debugging.

## 1.6. Tracing Middleware
[Tracing](pkg/tracing) middleware is responsible for instrumenting HTTP requests with OpenTelemetry tracing.
It captures key request details, such as the request method, URL, and remote address, allowing for distributed
tracing and improved observability. By integrating with OpenTelemetry, this middleware helps track request flows
across services, making it easier to debug performance bottlenecks and failures.

## 2. Authentication package

[Authentication](pkg/authentication) is an authentication package that uses claims and JWT to manage user
authentication.

It holds a middleware subpackages for handling JSON Web Tokens (JWT) to securely authenticate and authorize
HTTP and HTTPS requests, ensuring that only valid and properly signed tokens are processed for
access control and user verification.

## 2.1. Context JWT Authentication
[Authentication](pkg/authentication/context) is a middleware that uses JWT tokens to validate users authentication
using context and claims.

## 2.2. Redis JWT Authentication
[Authentication](pkg/authentication/redis) is a middleware that uses context claims with Redis cache to validate
JWT logged in tokens.
