# 阶段1：构建二进制文件和依赖
FROM node:20-alpine AS builder
ARG TARGETARCH

# 安装构建工具（Alpine 包名）
RUN apk add --no-cache \
    curl \
    unzip \
    xz \
    binutils \
    ca-certificates

# 环境变量
ENV FILE_PATH=/data \
    APP_DIR=/app \
    XRAY_ZIP_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip" \
    CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64"

# 下载并精简 Xray（适配 Alpine 架构）
RUN XRAY_TMP="/tmp/xray" \
    && mkdir -p /opt/bin /opt/share/xray "${XRAY_TMP}" \
    && if [ "$TARGETARCH" = "arm64" ]; then \
        XRAY_ZIP_URL="https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-arm64-v8a.zip"; \
       fi \
    && curl -fsSL "$XRAY_ZIP_URL" -o "${XRAY_TMP}/xray.zip" \
    && unzip -q "${XRAY_TMP}/xray.zip" -d "${XRAY_TMP}" \
    && install -m 755 "${XRAY_TMP}/xray" /opt/bin/xray \
    && install -m 644 "${XRAY_TMP}/geoip.dat" /opt/share/xray/geoip.dat \
    && install -m 644 "${XRAY_TMP}/geosite.dat" /opt/share/xray/geosite.dat \
    && strip --strip-unneeded /opt/bin/xray \
    && rm -rf "${XRAY_TMP}"

# 下载并精简 cloudflared
RUN mkdir -p /opt/bin \
    && if [ "$TARGETARCH" = "arm64" ]; then \
        CLOUDFLARED_URL="https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-arm64"; \
       fi \
    && curl -fsSL "$CLOUDFLARED_URL" -o /opt/bin/cloudflared \
    && chmod +x /opt/bin/cloudflared \
    && strip --strip-unneeded /opt/bin/cloudflared || true

# 安装 Node.js 依赖（优化层缓存）
WORKDIR ${APP_DIR}
COPY package*.json ./
RUN npm ci --omit=dev --cache /tmp/.npm \
    && rm -rf /tmp/.npm

# 复制源代码
COPY src ./src

# 阶段2：运行时镜像
FROM node:20-alpine AS runtime
ENV FILE_PATH=/data \
    NODE_ENV=production

# 从构建阶段复制二进制文件和依赖
COPY --from=builder /opt/bin/xray /usr/local/bin/xray
COPY --from=builder /opt/bin/cloudflared /usr/local/bin/cloudflared
COPY --from=builder /opt/share/xray /usr/local/share/xray
COPY --from=builder /app /app

# 设置工作目录和卷
WORKDIR /app
VOLUME ["/data"]
EXPOSE 3000 8001

# 非 root 用户运行（增强安全性）
RUN addgroup -g 1001 -S appuser && adduser -u 1001 -S appuser -G appuser \
    && chown -R appuser:appuser /app
USER appuser

CMD ["src/index.js"]