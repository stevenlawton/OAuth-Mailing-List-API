# Stage 1: Build the Go application
FROM golang:1.23 AS builder

WORKDIR /app

# Copy and download dependency modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN go build -o mailing-list-backend

# Stage 2: Run unit tests
FROM builder AS tester

# Run tests
RUN go test -v ./...

# Stage 3: Run the application in a minimal container
FROM scratch AS runner

# Copy executable from builder
COPY --from=builder /app/mailing-list-backend /mailing-list-backend

# Run the application
ENTRYPOINT ["/mailing-list-backend"]
