FROM node:22-alpine AS web

WORKDIR /src
COPY internal/version/VERSION ./internal/version/VERSION
COPY scripts/version.mjs ./scripts/version.mjs
COPY CHANGELOG.md ./CHANGELOG.md
COPY web/package.json web/package-lock.json ./web/
WORKDIR /src/web
RUN npm ci
COPY web/ ./
RUN npm run build

FROM golang:1.27-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG COMMIT=dev
ARG BUILD_DATE
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags "-s -w -X github.com/BaiLi-Labs/GuiLiu/internal/version.Commit=${COMMIT} -X github.com/BaiLi-Labs/GuiLiu/internal/version.BuildDate=${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}" \
    -o /out/guiliu ./cmd/guiliu

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && addgroup -S guiliu \
    && adduser -S -G guiliu guiliu \
    && mkdir -p /data \
    && chown guiliu:guiliu /data
COPY --from=build /out/guiliu /usr/local/bin/guiliu
COPY LICENSE NOTICE /licenses/

USER guiliu
WORKDIR /app
ENV GUILIU_LISTEN=0.0.0.0:8080 \
    GUILIU_DATABASE=/data/guiliu.db \
    GUILIU_SECRET_KEY_FILE=/data/secret.key

VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["guiliu"]
CMD ["serve"]
