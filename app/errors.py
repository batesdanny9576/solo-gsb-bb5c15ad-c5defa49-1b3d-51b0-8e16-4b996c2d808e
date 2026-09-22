"""统一的服务错误模型。

所有对外错误都使用同一信封::

    {"error": {"code": "...", "message": "...", "<定位字段>": ...}}
"""

from __future__ import annotations

from typing import Any


class ServiceError(Exception):
    """业务逻辑错误，携带稳定的机器可读 code 与定位信息。"""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        **details: Any,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details

    def to_body(self) -> dict[str, Any]:
        body: dict[str, Any] = {"code": self.code, "message": self.message}
        body.update(self.details)
        return {"error": body}
