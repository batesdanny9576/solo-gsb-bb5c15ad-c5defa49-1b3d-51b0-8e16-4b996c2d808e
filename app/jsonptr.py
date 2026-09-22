"""RFC 6901 JSON Pointer。

支持：

* 解析/转义（``~1`` -> ``/``，``~0`` -> ``~``，严格拒绝残缺转义）；
* 在已解析的 JSON 文档上定位值；
* 区分“路径语法错误 / 不存在 / 父节点是标量 / 数组下标非法”，
  以便错误响应能够精确定位到失败的指针段。
"""

from __future__ import annotations

from typing import Any

from .errors import ServiceError


class PointerError(ServiceError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        pointer: str = "",
        token: str | None = None,
        token_index: int | None = None,
    ) -> None:
        details: dict[str, Any] = {"pointer": pointer}
        if token is not None:
            details["token"] = token
        if token_index is not None:
            details["token_index"] = token_index
        super().__init__(code, message, 400, **details)


def parse(pointer: str) -> list[str]:
    """把 RFC 6901 指针解析为引用 token 列表。

    空串表示整个文档；非空指针必须以 ``/`` 开头。
    """
    if pointer == "":
        return []
    if not pointer.startswith("/"):
        raise PointerError(
            "INVALID_POINTER_SYNTAX",
            "非空 JSON Pointer 必须以 '/' 开头。",
            pointer=pointer,
        )
    tokens: list[str] = []
    raw_tokens = pointer[1:].split("/")
    for idx, raw in enumerate(raw_tokens):
        token: list[str] = []
        i = 0
        while i < len(raw):
            ch = raw[i]
            if ch == "~":
                if i + 1 >= len(raw) or raw[i + 1] not in "01":
                    raise PointerError(
                        "INVALID_POINTER_SYNTAX",
                        "非法转义：'~' 后只能是 '0' 或 '1'。",
                        pointer=pointer,
                        token=raw,
                        token_index=idx,
                    )
                token.append("/" if raw[i + 1] == "1" else "~")
                i += 2
            else:
                token.append(ch)
                i += 1
        tokens.append("".join(token))
    return tokens


def escape(token: str) -> str:
    """把单个属性名转义为指针 token（先转 ~ 再转 /）。"""
    return token.replace("~", "~0").replace("/", "~1")


def build(tokens: list[str]) -> str:
    if not tokens:
        return ""
    return "".join("/" + escape(t) for t in tokens)


def _array_index(token: str) -> int | None:
    """按 RFC 6901 校验数组下标；非法时返回 None。"""
    if token == "":
        return None  # '-' 也不匹配，下面单独处理
    if token == "-":
        return -1  # RFC 6901：'-' 指向数组末尾之后，对取值总是“不存在”
    if not all("0" <= c <= "9" for c in token):
        return None
    if len(token) > 1 and token[0] == "0":
        return None  # 不允许前导零
    return int(token)


def resolve(document: Any, pointer: str) -> Any:
    """按指针定位并返回值，失败抛出可定位的 PointerError。"""
    tokens = parse(pointer)
    current = document
    prefix_tokens: list[str] = []
    for idx, token in enumerate(tokens):
        if isinstance(current, dict):
            if token not in current:
                raise PointerError(
                    "POINTER_NOT_FOUND",
                    f"对象在路径 {build(prefix_tokens)!r} 下不存在键 {token!r}。",
                    pointer=pointer,
                    token=token,
                    token_index=idx,
                )
            current = current[token]
        elif isinstance(current, list):
            index = _array_index(token)
            if index is None or index < 0 or index >= len(current):
                code = "POINTER_NOT_FOUND"
                message = (
                    f"数组在路径 {build(prefix_tokens)!r} 下不存在下标 {token!r}。"
                )
                if token == "-":
                    message = "'-' 指向数组末尾之后，不可用于取值。"
                raise PointerError(
                    code,
                    message,
                    pointer=pointer,
                    token=token,
                    token_index=idx,
                )
            current = current[index]
        else:
            raise PointerError(
                "POINTER_PARENT_SCALAR",
                f"路径 {build(prefix_tokens)!r} 处是标量，无法继续解析 {token!r}。",
                pointer=pointer,
                token=token,
                token_index=idx,
            )
        prefix_tokens.append(token)
    return current


def is_leaf(value: Any) -> bool:
    """叶节点：标量，或空对象/空数组（RFC 要求空容器作为叶子披露）。"""
    return not isinstance(value, (dict, list)) or len(value) == 0
