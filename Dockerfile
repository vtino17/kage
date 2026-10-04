FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /kage ./cmd/kage

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 kage
COPY --from=builder /kage /usr/local/bin/kage
USER kage
ENTRYPOINT ["kage"]
CMD ["--help"]
