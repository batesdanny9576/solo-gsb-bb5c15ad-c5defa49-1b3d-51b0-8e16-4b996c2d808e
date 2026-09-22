"""请求/响应 Pydantic 模型。"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# JSON 值：bool / int / float / str / None / list / dict
JSONValue = Any


class DiscloseRequest(BaseModel):
    document: JSONValue = Field(
        ..., description="待计算承诺根的嵌套 JSON 文档。"
    )
    paths: list[str] = Field(
        ...,
        min_length=1,
        description="请求披露的 RFC 6901 路径数组；每项必须指向叶子（标量/空容器），不可重复。",
    )


class ProofStepOut(BaseModel):
    sibling: str = Field(..., description="兄弟节点哈希（64 位 hex SHA-256）。")
    side: str = Field(
        ...,
        description="'L' 表示当前节点是左孩子（兄弟在右）；'R' 反之。",
    )
    node: str = Field(..., description="本步组合后应得到的父节点哈希。")


class ProofOut(BaseModel):
    path: str
    value: JSONValue
    leaf_hash: str = Field(..., description="长度前缀编码重算出的叶子哈希。")
    steps: list[ProofStepOut]


class DiscloseResponse(BaseModel):
    root: str
    leaf_count: int
    disclosures: list[ProofOut]


class VerifyRequest(BaseModel):
    root: str = Field(..., description="承诺根哈希（64 位 hex）。")
    proof: ProofOut


class VerifyResponse(BaseModel):
    valid: bool = True
    root: str
    leaf_hash: str
    steps_verified: int
