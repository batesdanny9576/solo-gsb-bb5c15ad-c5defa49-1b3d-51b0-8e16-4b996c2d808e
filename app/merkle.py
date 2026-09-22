"""Merkle 树：叶展开、长度前缀编码、可复现根与包含证明。

编码约定（全部为字节级，哈希统一 SHA-256，输出小写 hex）：

* 叶节点（“叶子”= 标量、空对象、空数组）：

  ``SHA256( 0x00 || u32be(len(path)) || path_utf8
           || u32be(len(cjson)) || cjson_utf8 )``

  其中 ``path`` 是 RFC 6901 指针（根值为空串），``cjson`` 是
  :mod:`app.canonical` 产出的规范 JSON 值。长度前缀为 4 字节大端无符号整数。

* 内部节点（域分离，避免与叶子混淆）：

  ``SHA256( 0x01 || left_hash || right_hash )``

* 叶子按路径的 UTF-8 字节序排序后从左到右入树；
* 某一层节点数为奇数时，复制最后一个节点参与配对；
* 单叶子文档的根即该叶子哈希；
* 空文档定义为 ``SHA256("")``。

证明中的每个步骤给出兄弟哈希及拼接方向（"L" 表示当前节点是左孩子，
"S" 表示兄弟节点在右；"R" 反之）。此外每一步额外给出组合后应得到的
``node`` 哈希，使校验失败可精确定位到被篡改的步骤；不使用 ``node``
字段的标准验证器同样可以完成校验，最后与根比对即可。
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from typing import Any

from . import canonical, jsonptr
from .errors import ServiceError

EMPTY_ROOT = hashlib.sha256(b"").hexdigest()
_DOMAIN_LEAF = b"\x00"
_DOMAIN_NODE = b"\x01"
_u32be = lambda n: struct.pack(">I", n)


# ---------------------------------------------------------------------------
# 叶展开
# ---------------------------------------------------------------------------


def flatten(document: Any) -> list[tuple[str, Any]]:
    """展开文档为 ``(RFC6901 路径, 叶值)`` 列表并按路径 UTF-8 字节序排序。

    标量、空对象、空数组都是叶子；非空容器继续递归。
    """
    entries: list[tuple[str, Any]] = []

    def walk(value: Any, tokens: list[str]) -> None:
        if jsonptr.is_leaf(value):
            entries.append((jsonptr.build(tokens), value))
            return
        if isinstance(value, dict):
            for key in value:
                walk(value[key], tokens + [key])
        else:  # list
            for index, item in enumerate(value):
                walk(item, tokens + [str(index)])

    walk(document, [])
    entries.sort(key=lambda entry: entry[0].encode("utf-8"))
    return entries


# ---------------------------------------------------------------------------
# 哈希
# ---------------------------------------------------------------------------


def leaf_hash(pointer: str, value: Any) -> str:
    """长度前缀编码的“路径 + 规范 JSON 值”叶哈希。"""
    path_bytes = pointer.encode("utf-8")
    cjson_bytes = canonical.dumps(value).encode("utf-8")
    digest = hashlib.sha256()
    digest.update(_DOMAIN_LEAF)
    digest.update(_u32be(len(path_bytes)))
    digest.update(path_bytes)
    digest.update(_u32be(len(cjson_bytes)))
    digest.update(cjson_bytes)
    return digest.hexdigest()


def pair_hash(left: str, right: str) -> str:
    digest = hashlib.sha256()
    digest.update(_DOMAIN_NODE)
    digest.update(bytes.fromhex(left))
    digest.update(bytes.fromhex(right))
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# 建树与证明
# ---------------------------------------------------------------------------


@dataclass
class ProofStep:
    sibling: str
    side: str  # "L": 当前节点在左、兄弟在右；"R": 当前节点在右、兄弟在左
    node: str  # 本层组合后应得到的节点哈希（用于精确定位篡改）

    def as_dict(self) -> dict[str, str]:
        return {"sibling": self.sibling, "side": self.side, "node": self.node}


@dataclass
class MerkleTree:
    root: str
    # RFC6901 路径 -> 证明步骤
    proofs: dict[str, list[ProofStep]]


def build_tree(document: Any) -> MerkleTree:
    leaves = flatten(document)
    if not leaves:
        # 合法 JSON 至少有一个叶子；保留空根定义以备边界情况。
        return MerkleTree(root=EMPTY_ROOT, proofs={})

    # 每层元素为 (哈希, 该物理节点覆盖的叶子路径集合)。
    level: list[tuple[str, set[str]]] = [
        (leaf_hash(path, value), {path}) for path, value in leaves
    ]
    proof_steps: dict[str, list[ProofStep]] = {
        path: [] for path, _ in leaves
    }

    while len(level) > 1:
        if len(level) % 2 == 1:
            # 奇数节点：复制末节点（哈希相同；路径集合保持同一份语义）。
            last_hash, last_paths = level[-1]
            level.append((last_hash, set(last_paths)))

        next_level: list[tuple[str, set[str]]] = []
        for i in range(0, len(level), 2):
            left_hash, left_paths = level[i]
            right_hash, right_paths = level[i + 1]
            parent = pair_hash(left_hash, right_hash)
            parent_paths = left_paths | right_paths
            next_level.append((parent, parent_paths))

            for path in parent_paths:
                if path in left_paths:
                    # 被复制的末节点同时出现在两侧：两侧哈希相同，
                    # 确定性地选择 L，只记录一步。
                    proof_steps[path].append(
                        ProofStep(sibling=right_hash, side="L", node=parent)
                    )
                else:
                    proof_steps[path].append(
                        ProofStep(sibling=left_hash, side="R", node=parent)
                    )

        level = next_level

    return MerkleTree(root=level[0][0], proofs=proof_steps)


# ---------------------------------------------------------------------------
# 证明校验（不接触原始文档）
# ---------------------------------------------------------------------------


def _is_hex_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(c in "0123456789abcdefABCDEF" for c in value)
    )


def verify_inclusion(
    pointer: str,
    value: Any,
    steps: list[dict[str, Any]],
    expected_root: str,
) -> str:
    """验证包含证明。成功返回最终根哈希；失败抛出带 step 定位的 ServiceError。"""
    if not _is_hex_hash(expected_root):
        raise ServiceError(
            "INVALID_ROOT",
            "root 必须是 64 位十六进制 SHA-256 摘要。",
            400,
        )
    expected_root = expected_root.lower()

    try:
        current = leaf_hash(pointer, value)
    except ServiceError as exc:
        raise ServiceError(
            "LEAF_HASH_ERROR",
            f"无法由 path/value 重算叶哈希：{exc.message}",
            400,
        ) from exc

    if not isinstance(steps, list):
        raise ServiceError(
            "MALFORMED_PROOF",
            "proof.steps 必须是数组。",
            400,
        )

    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ServiceError(
                "MALFORMED_PROOF",
                "证明步骤必须是对象。",
                400,
                step=index,
            )
        sibling = step.get("sibling")
        side = step.get("side")
        if not _is_hex_hash(sibling):
            raise ServiceError(
                "MALFORMED_PROOF",
                "step.sibling 必须是 64 位十六进制哈希。",
                400,
                step=index,
            )
        if side not in ("L", "R"):
            raise ServiceError(
                "MALFORMED_PROOF",
                "step.side 必须是 'L' 或 'R'。",
                400,
                step=index,
            )

        sibling = sibling.lower()
        if side == "L":
            computed = pair_hash(current, sibling)
        else:
            computed = pair_hash(sibling, current)

        node = step.get("node")
        if node is not None:
            if not _is_hex_hash(node):
                raise ServiceError(
                    "MALFORMED_PROOF",
                    "step.node 若提供，必须是 64 位十六进制哈希。",
                    400,
                    step=index,
                )
            if node.lower() != computed:
                raise ServiceError(
                    "PROOF_STEP_MISMATCH",
                    f"第 {index} 步组合哈希与该步声明的 node 不一致，"
                    "兄弟节点或当前节点已被篡改。",
                    400,
                    step=index,
                    expected_node=node.lower(),
                    computed_node=computed,
                )
        current = computed

    if current.lower() != expected_root:
        raise ServiceError(
            "ROOT_MISMATCH",
            "证明重算出的根与提供的 root 不一致；路径、值、兄弟节点或根可能被篡改。",
            400,
            expected_root=expected_root,
            computed_root=current.lower(),
        )
    return current.lower()
