# Build on the target platform so cgo and the native SDK share an ABI.
FROM golang:1.26-bookworm AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN apt-get update && apt-get install -y --no-install-recommends \
    make gcc libc6-dev pkg-config ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN make native-sdk && make build-static

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/deskconn-router /deskconn-router
WORKDIR /app

ENTRYPOINT ["/deskconn-router"]
