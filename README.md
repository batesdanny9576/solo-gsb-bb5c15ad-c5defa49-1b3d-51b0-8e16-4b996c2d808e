# 选择性 JSON 事实披露服务（FastAPI）

提交一份嵌套 JSON 与待披露路径，服务会：

1. 按 **RFC 6901** 路径把文档展开为叶子——**标量、空对象 `{}`、空数组 `[]` 都是叶子**；
2. 对每片叶子用**长度前缀编码**的「路径 + 规范 JSON（Canonical JSON, RFC 8785 规则）值」计算 SHA-256 叶哈希；
3. 叶子按路径排序，自底向上配对成 **Merkle 树**，根可复现；**奇数节点层复制末节点**参与配对；
4. `/disclose` 的响应**只包含所选叶子的值与包含证明**，不返回文档其余部分；
5. `/verify` 仅凭 `root + proof` 校验证明，**全程不接触原始文档**；路径、值、兄弟节点或根被篡改都会被拒绝，错误可定位到具体路径段或证明步骤。

---

## 一条命令启动

```bash
docker compose up --build
```

依赖（FastAPI / uvicorn / pydantic，见 `requirements.txt`）在**容器启动时自动安装**，无需手工 `pip install`。

启动后：

| 用途 | 地址 |
| --- | --- |
| API 基础地址 | `http://localhost:8000` |
| 健康检查 | `GET http://localhost:8000/health` |
| 交互式文档（Swagger UI） | `http://localhost:8000/docs` |
| OpenAPI 模式 | `http://localhost:8000/openapi.json` |

## 必要配置（均可省略，使用默认值）

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `PORT`（Compose 变量） | `8000` | 宿主机暴露端口，例如 `PORT=9000 docker compose up --build` |
| `UVI_HOST` | `0.0.0.0` | 容器内监听地址 |
| `UVI_PORT` | `8000` | 容器内监听端口（Compose 固定映射到此端口） |

无需数据库、无需外部服务。

---

## API

### `POST /disclose` — 生成根与选择性披露证明

请求：

```json
{
  "document": {
    "name": "alice",
    "age": 30,
    "tags": ["a", "b", "c"],
    "empty_obj": {},
    "empty_arr": [],
    "nested": {"x": 1, "y": {"z": true, "w": null}}
  },
  "paths": ["/name", "/tags/2", "/empty_obj"]
}
```

响应只含承诺根、叶数量和**所请求路径**的值与证明：

```json
{
  "root": "a0215690…6965",
  "leaf_count": 10,
  "disclosures": [
    {
      "path": "/name",
      "value": "alice",
      "leaf_hash": "…",
      "steps": [
        {"sibling": "<64位hex>", "side": "L", "node": "<64位hex>"}
      ]
    }
  ]
}
```

`side`：`"L"` 表示当前节点是左孩子（兄弟在右），`"R"` 反之；`node` 是本步组合后应得到的父哈希（用于精确定位篡改步骤，标准验证器可忽略它，仅与根比对）。

### `POST /verify` — 无原文校验

验证方只需要承诺方公开的 `root` 与某一条 disclosure：

```json
{
  "root": "a0215690…6965",
  "proof": {
    "path": "/name",
    "value": "alice",
    "leaf_hash": "…",
    "steps": [ {"sibling": "…", "side": "L", "node": "…"} ]
  }
}
```

成功：`200 {"valid": true, "root": "…", "leaf_hash": "…", "steps_verified": 4}`。
失败：`400`，统一错误信封（见下）。

### curl 速览

```bash
# 1) 披露
curl -s http://localhost:8000/disclose \
  -H 'Content-Type: application/json' \
  -d '{"document":{"name":"alice","age":30,"tags":["a","b","c"]},
       "paths":["/name","/tags/2"]}'

# 2) 把上一步返回的 root 与 disclosures[i] 原样交给 /verify
curl -s http://localhost:8000/verify \
  -H 'Content-Type: application/json' \
  -d '{"root":"<root>","proof":<disclosures[i]>}'
```

---

## 密码学约定（字节级，可跨实现复现）

哈希统一为 SHA-256，输出小写 hex。

**叶哈希**（长度前缀编码，长度前缀为 4 字节大端无符号整数）：

```
leaf = SHA256( 0x00
               || u32be(len(path_utf8))  || path_utf8
               || u32be(len(cjson_utf8)) || cjson_utf8 )
```

- `path`：RFC 6901 指针；根值（整篇文档即标量/空容器时）为空串 `""`。
- `cjson`：规范 JSON 值——无空白、对象键按 UTF-16BE 码元序（RFC 8785 / JCS）排序、
  `1.0 → 1`、`-0 → 0`、指数无多余 `+`/前导零；`NaN/Infinity` 被拒绝。

**内部节点**（域分离前缀，避免叶子/内部节点互相伪造）：

```
node = SHA256( 0x01 || left_hash(32B) || right_hash(32B) )
```

**建树规则**：

1. 叶子按路径的 UTF-8 字节序排序；
2. 每层从左到右两两配对；节点数为奇数时**复制最后一个节点**（与自身配对）；
3. 单叶子文档的根即叶哈希；空根定义为 `SHA256("")`。

同一文档任意时刻重建得到相同的根。

## 篡改如何被拒绝与定位

所有错误使用统一信封：

```json
{"error": {"code": "PROOF_STEP_MISMATCH", "message": "…", "step": 0, "expected_node": "…", "computed_node": "…"}}
```

| 篡改方式 | 拒绝结果 |
| --- | --- |
| 改 `value` / `path` | 重算叶哈希不同 → `PROOF_STEP_MISMATCH`（通常在第 0 步）或 `ROOT_MISMATCH` |
| 改某步 `sibling` | `PROOF_STEP_MISMATCH`，`error.step` 指出**具体步骤**，并给出 expected/computed 哈希 |
| 改 `side` / 哈希格式错误 | `MALFORMED_PROOF`（带 `step`） |
| 改 `root` | `ROOT_MISMATCH`，同时返回 `expected_root` 与 `computed_root` |
| 指针路径不存在 / 父节点是标量 / 数组下标非法 | `POINTER_NOT_FOUND` / `POINTER_PARENT_SCALAR`，带 `pointer`、`token`、`token_index` |
| 指针语法错误（缺前导 `/`、残缺 `~` 转义等） | `INVALID_POINTER_SYNTAX`，带出错的 `token_index` |
| 请求结构错误 | `INVALID_REQUEST`，`location`/`locations` 指出字段 |
| 请求体不是 JSON | `INVALID_JSON` |
| 披露路径指向非空容器 | `NOT_A_LEAF`（只能披露标量、空对象、空数组） |
| 路径重复 | `DUPLICATE_PATH`（带 `index`） |

> 说明：验证接口只做指针**语法**检查，不持有也不解析原文档——这正是选择性披露的要求。

---

## 本地开发（不使用 Docker）

```bash
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --port 8000
```

运行测试（仅标准库，无需第三方依赖）：

```bash
python -m unittest discover -s tests -v
```

## 项目结构

```
app/
  canonical.py   # 规范 JSON 序列化（RFC 8785 规则）
  jsonptr.py     # RFC 6901 指针解析、定位、可定位错误
  merkle.py      # 叶展开、长度前缀哈希、Merkle 根、证明生成与校验
  schemas.py     # 请求/响应模型
  main.py        # FastAPI 路由与统一错误信封
  errors.py
tests/test_merkle.py
Dockerfile  docker-entrypoint.sh  docker-compose.yml  requirements.txt
```
