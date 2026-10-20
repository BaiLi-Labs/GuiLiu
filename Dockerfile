FROM node:22-alpine AS web

WORKDIR /web
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /web/dist ./web/dist
ARG VERSION=dev
ARG COMMIT=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/BaiLi-Labs/GuiLiu/internal/version.Version=${VERSION} -X github.com/BaiLi-Labs/GuiLiu/internal/version.Commit=${COMMIT}" \
    -o /out/guiliu ./cmd/guiliu

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && addgroup -S guiliu \
    && adduser -S -G guiliu guiliu \
    && mkdir -p /data \
    && chown guiliu:guiliu /data
COPY --from=build /out/guiliu /usr/local/bin/guiliu

USER guiliu
WORKDIR /app
ENV GUILIU_LISTEN=0.0.0.0:8080 \
    GUILIU_DATABASE=/data/guiliu.db \
    GUILIU_SECRET_KEY_FILE=/data/secret.key

VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["guiliu"]
CMD ["serve"]
