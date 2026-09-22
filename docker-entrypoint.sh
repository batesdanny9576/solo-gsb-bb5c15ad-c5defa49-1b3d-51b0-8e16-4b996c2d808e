#!/bin/sh
# 容器入口：启动时安装依赖，随后启动 uvicorn。
set -e

echo "[entrypoint] Installing dependencies from requirements.txt ..."
python -m pip install -r requirements.txt

HOST="${UVI_HOST:-0.0.0.0}"
PORT="${UVI_PORT:-8000}"

echo "[entrypoint] Starting uvicorn on ${HOST}:${PORT} ..."
exec python -m uvicorn app.main:app --host "${HOST}" --port "${PORT}"
