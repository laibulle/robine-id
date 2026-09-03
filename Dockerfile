FROM golang:1.27.1-alpine AS builder

RUN apk add --no-cache ca-certificates git
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd cmd
COPY internal internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/robine-id ./cmd/robine-id

FROM alpine:3.22 AS final

RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S robine-id \
    && adduser -S -G robine-id -h /app robine-id \
    && mkdir -p /app/config /data \
    && chown -R robine-id:robine-id /app /data

WORKDIR /app
COPY --from=builder --chown=robine-id:robine-id /out/robine-id /app/robine-id

USER robine-id
ENV PORT=8080 \
    ROBINE_ID_BLOB_STORE=local \
    ROBINE_ID_STORAGE_ROOT=/config \
    ROBINE_ID_CONFIG_KEY=robine_id.json \
    ROBINE_ID_APPLICATIONS_PREFIX=applications \
    ROBINE_ID_STATE_ROOT=/data \
    ROBINE_ID_SIGNING_KEY=signing_keys.json.enc \
    ROBINE_ID_ACCOUNTS_KEY=accounts.json

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=3s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/health/ready || exit 1

ENTRYPOINT ["/app/robine-id"]
