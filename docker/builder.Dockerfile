# ctfir Linux 构建宿主镜像（固定 tag，可复现）
FROM alpine:3.20
RUN apk add --no-cache g++ musl-dev cmake ninja
