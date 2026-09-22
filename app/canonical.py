"""规范 JSON（Canonical JSON）序列化。

采用 RFC 8785（JCS）的核心规则：

* 无意义空白、对象键按 UTF-8 字节序（等价于按 Unicode 码位序）排序；
* UTF-8 文本，字符串按 JSON 转义规则；
* 整数按整数写出，1.0 规范化为 ``1``，-0 规范化为 ``0``；
* 浮点指数使用 ``e`` 记号且不带多余的符号/前导零。

本服务仅接受 JSON 原生类型（由请求解析保证），NaN/Infinity 直接拒绝，
因为它们不属于合法 JSON 且无法生成确定的规范表示。
"""

from __future__ import annotations

import math
from typing import Any

from .errors import ServiceError

ESCAPE = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _format_float(value: float) -> str:
    if not math.isfinite(value):
        raise ServiceError(
            "NON_FINITE_NUMBER",
            "NaN 与 Infinity 不属于合法 JSON，无法生成规范表示。",
            400,
        )
    if value == 0.0:
        # JCS：-0 规范化为 0
        return "0"
    text = repr(float(value))
    if "e" in text:
        mantissa, exponent = text.split("e", 1)
        exp = int(exponent)
        text = f"{mantissa}e{exp}"  # 去掉 Python 的指数前导零与 '+'
    if text.endswith(".0"):
        text = text[:-2]
    return text


def _encode_string(value: str) -> str:
    out = ['"']
    for ch in value:
        code = ord(ch)
        if code in ESCAPE:
            out.append(ESCAPE[code])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def dumps(value: Any) -> str:
    """把 JSON 原生值序列化为紧凑、确定的规范 JSON 字节串（文本）。"""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return _format_float(value)
    if isinstance(value, list):
        return "[" + ",".join(dumps(item) for item in value) + "]"
    if isinstance(value, dict):
        # JCS：键按 UTF-16BE 字节序（即 UTF-16 代码单元序）排序。
        # 注意增补平面字符在代理对区间，排序结果与 Unicode 码位序不同。
        ordered_keys = sorted(value.keys(), key=lambda k: k.encode("utf-16-be"))
        parts = [f"{_encode_string(k)}:{dumps(value[k])}" for k in ordered_keys]
        return "{" + ",".join(parts) + "}"
    raise ServiceError(
        "UNSUPPORTED_JSON_TYPE",
        f"无法规范化类型 {type(value).__name__}，仅支持 JSON 原生类型。",
        400,
    )
