# Stage 1: Build the Go application
FROM golang:1.23 AS builder

WORKDIR /app

# Copy and download dependency modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mailing-list-backend

# Stage 3: Run the application in a minimal container
FROM golang:alpine3.20 AS runner

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

WORKDIR /app

# Copy executable from builder
COPY --from=builder /app/mailing-list-backend .

# Set executable permissions (just in case)
RUN chmod +x mailing-list-backend

# Run the application
ENTRYPOINT ["./mailing-list-backend"]
