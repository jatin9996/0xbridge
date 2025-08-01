# Build stage
FROM golang:1.24.5-alpine AS builder

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o 0xbridge main.go

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Create non-root user
RUN addgroup -g 1001 -S 0xbridge && \
    adduser -u 1001 -S 0xbridge -G 0xbridge

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/0xbridge .

# Change ownership to non-root user
RUN chown -R 0xbridge:0xbridge /app

# Switch to non-root user
USER 0xbridge

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/avs/status || exit 1

# Run the application
CMD ["./0xbridge"] 