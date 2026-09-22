"""FastAPI 应用：选择性披露与无原文证明校验。"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from . import jsonptr, merkle
from .errors import ServiceError
from .schemas import (
    DiscloseRequest,
    DiscloseResponse,
    ProofOut,
    ProofStepOut,
    VerifyRequest,
    VerifyResponse,
)

app = FastAPI(
    title="Selective JSON Disclosure",
    description=(
        "对嵌套 JSON 生成 RFC 6901 叶子承诺（Merkle 根），"
        "并提供仅含所选值的包含证明；校验接口无需接触原始文档。"
    ),
    version="1.0.0",
)


@app.exception_handler(ServiceError)
async def service_error_handler(_: Request, exc: ServiceError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content=exc.to_body())


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    _: Request, exc: RequestValidationError
) -> JSONResponse:
    """把 422 规整为统一信封，并在 error.location 中定位出错字段。"""
    locations: list[str] = []
    for err in exc.errors():
        loc = ".".join(str(part) for part in err["loc"] if part != "body")
        locations.append(loc or "$")
    first = exc.errors()[0] if exc.errors() else {}
    message = first.get("msg", "请求体不符合接口模式。")
    return JSONResponse(
        status_code=400,
        content={
            "error": {
                "code": "INVALID_REQUEST",
                "message": message,
                "location": locations[0] if locations else "$",
                "locations": locations,
            }
        },
    )


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/disclose", response_model=DiscloseResponse)
async def disclose(raw: Request) -> dict[str, Any]:
    try:
        payload = await raw.json()
    except Exception:  # noqa: BLE001 - 任意解析失败都转换为统一错误
        raise ServiceError(
            "INVALID_JSON", "请求体必须是合法 JSON。", 400
        ) from None

    try:
        request = DiscloseRequest.model_validate(payload)
    except ValidationError as exc:
        # 复用统一信封
        errors = exc.errors()
        locations = [
            ".".join(str(part) for part in e["loc"] if part != "body") or "$"
            for e in errors
        ]
        first = errors[0]
        raise ServiceError(
            "INVALID_REQUEST",
            first.get("msg", "请求体不符合接口模式。"),
            400,
            location=locations[0] if locations else "$",
            locations=locations,
        ) from None

    # 路径去重检查（顺序保留）
    seen: set[str] = set()
    for index, path in enumerate(request.paths):
        if path in seen:
            raise ServiceError(
                "DUPLICATE_PATH",
                f"路径 {path!r} 在请求中重复出现。",
                400,
                path=path,
                index=index,
            )
        seen.add(path)

    tree = merkle.build_tree(request.document)

    disclosures: list[dict[str, Any]] = []
    for path in request.paths:
        # 语法解析（严格 RFC 6901）
        jsonptr.parse(path)
        value = jsonptr.resolve(request.document, path)
        if not jsonptr.is_leaf(value):
            raise ServiceError(
                "NOT_A_LEAF",
                (
                    f"路径 {path!r} 指向非空容器，只能披露叶子"
                    "（标量、空对象或空数组）。"
                ),
                400,
                path=path,
            )
        steps = tree.proofs[path]
        disclosures.append(
            {
                "path": path,
                "value": value,
                "leaf_hash": merkle.leaf_hash(path, value),
                "steps": [step.as_dict() for step in steps],
            }
        )

    return {
        "root": tree.root,
        "leaf_count": len(merkle.flatten(request.document)),
        "disclosures": disclosures,
    }


@app.post("/verify", response_model=VerifyResponse)
async def verify(raw: Request) -> dict[str, Any]:
    try:
        payload = await raw.json()
    except Exception:  # noqa: BLE001
        raise ServiceError(
            "INVALID_JSON", "请求体必须是合法 JSON。", 400
        ) from None

    try:
        request = VerifyRequest.model_validate(payload)
    except ValidationError as exc:
        errors = exc.errors()
        locations = [
            ".".join(str(part) for part in e["loc"] if part != "body") or "$"
            for e in errors
        ]
        first = errors[0]
        raise ServiceError(
            "INVALID_REQUEST",
            first.get("msg", "请求体不符合接口模式。"),
            400,
            location=locations[0] if locations else "$",
            locations=locations,
        ) from None

    proof = request.proof
    # 仅做指针语法校验：校验方绝不接触原始文档，也无法据此解析值。
    jsonptr.parse(proof.path)

    steps_raw = [step.model_dump() for step in proof.steps]
    root = merkle.verify_inclusion(
        pointer=proof.path,
        value=proof.value,
        steps=steps_raw,
        expected_root=request.root,
    )
    return {
        "valid": True,
        "root": root,
        "leaf_hash": merkle.leaf_hash(proof.path, proof.value),
        "steps_verified": len(proof.steps),
    }
