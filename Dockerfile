# Build stage
FROM golang:1.24-alpine AS builder

# Install libpcap-dev for live capture support (optional, but good to have)
RUN apk add --no-cache libpcap-dev gcc musl-dev

WORKDIR /app

# Copy go.mod and go.sum and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the forensics tool
RUN go build -o wiremind ./cmd/forensics/main.go

# Run stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache libpcap

WORKDIR /root/

# Copy the binary and necessary runtime files from the builder stage
COPY --from=builder /app/wiremind .
COPY --from=builder /app/config/config.yaml ./config/
RUN mkdir -p ./data/ioc ./output ./logs

# Expose the API port
EXPOSE 8765

# Set default environment variables
ENV DB_ENABLED=true
ENV REDIS_ENABLED=true

# Command to run the forensics server
ENTRYPOINT ["./wiremind"]
CMD ["parse", "--serve"]
