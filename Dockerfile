# --- Build stage ---
FROM golang:1.24.1-bullseye AS build

WORKDIR /app

# Кеширование модулей Go
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go env -w GOMODCACHE=/go/pkg/mod && \
    go env -w GOCACHE=/root/.cache/go-build

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify

COPY . .

# Сборка бинарника
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /main ./cmd/auth-service

# --- Runtime stage ---
FROM alpine:3.20 AS runtime

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Копируем бинарник
COPY --from=build /main /main

# Копируем JWT ключи (для dev, безопасно)
COPY private.pem public.pem /app/

EXPOSE 8080

CMD ["/main"]