# 轻量基础镜像；依赖在容器启动时安装（见 docker-entrypoint.sh）
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# 仅复制安装清单与启动脚本，便于利用层缓存
COPY requirements.txt docker-entrypoint.sh ./
COPY app ./app

RUN chmod +x docker-entrypoint.sh

# 8000：容器内固定监听端口（可通过 UVI_* 环境变量覆盖）
EXPOSE 8000

ENTRYPOINT ["./docker-entrypoint.sh"]
