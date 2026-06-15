# syntax=docker/dockerfile:1

# Build stage
FROM golang:1.26.4-alpine@sha256:7a3e50096189ad57c9f9f865e7e4aa8585ed1585248513dc5cda498e2f41812c AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY . .

# Accept build arguments
ARG VERSION=dev
ARG BUILD_TIME=unknown

# Build the application with version info
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build \
    -ldflags="-X main.version=${VERSION} -X main.buildTime=${BUILD_TIME} -s -w" \
    -o oauth-proxy .

# Final stage
FROM alpine:3.24.0@sha256:a2d49ea686c2adfe3c992e47dc3b5e7fa6e6b5055609400dc2acaeb241c829f4

# Install ca-certificates for HTTPS requests and apply security patches
RUN apk --no-cache add ca-certificates tzdata && apk upgrade --no-cache

# Create non-root user
RUN addgroup -g 1001 -S oauth && \
    adduser -u 1001 -S oauth -G oauth

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/oauth-proxy .

# Change ownership to non-root user
RUN chown -R oauth:oauth /app

# Switch to non-root user
USER oauth

# Expose port
EXPOSE 8080

# Run the application
CMD ["./oauth-proxy"]
