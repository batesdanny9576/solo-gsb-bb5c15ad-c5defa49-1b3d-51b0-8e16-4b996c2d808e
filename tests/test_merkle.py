"""Merkle 核心逻辑测试：可复现根、奇数层复制、证明往返、篡改定位。"""

import hashlib
import unittest

from app import canonical, jsonptr, merkle
from app.errors import ServiceError

DOC = {
    "name": "alice",
    "age": 30,
    "tags": ["a", "b", "c"],  # 3 个叶子 -> 奇数层
    "empty_obj": {},
    "empty_arr": [],
    "nested": {"x": 1, "y": {"z": True, "w": None}},
}


class CanonicalTests(unittest.TestCase):
    def test_key_order_and_compact(self) -> None:
        self.assertEqual(
            canonical.dumps({"b": 1, "a": [1, 2]}), '{"a":[1,2],"b":1}'
        )

    def test_scalars(self) -> None:
        self.assertEqual(canonical.dumps(None), "null")
        self.assertEqual(canonical.dumps(True), "true")
        self.assertEqual(canonical.dumps(False), "false")
        self.assertEqual(canonical.dumps(1.0), "1")
        self.assertEqual(canonical.dumps(-0.0), "0")

    def test_unicode_sorted(self) -> None:
        # U+00E9 在 BMP；增补字符 U+1F600 按 UTF-16 序排在 BMP 之后
        self.assertEqual(
            canonical.dumps({"é": 1, "a": 2, "\U0001f600": 3}),
            '{"a":2,"é":1,"\U0001f600":3}',
        )


class FlattenTests(unittest.TestCase):
    def test_empty_containers_are_leaves(self) -> None:
        entries = dict(merkle.flatten(DOC))
        self.assertIn("/empty_obj", entries)
        self.assertEqual(entries["/empty_obj"], {})
        self.assertIn("/empty_arr", entries)
        self.assertEqual(entries["/empty_arr"], [])
        self.assertNotIn("/nested/y", entries)  # 非空容器不是叶子
        self.assertIn("/nested/y/z", entries)

    def test_scalar_root(self) -> None:
        self.assertEqual(merkle.flatten(42), [("", 42)])
        self.assertEqual(merkle.flatten({}), [("", {})])
        self.assertEqual(merkle.flatten([]), [("", [])])

    def test_sorted_by_path(self) -> None:
        paths = [p for p, _ in merkle.flatten(DOC)]
        self.assertEqual(paths, sorted(paths, key=lambda p: p.encode()))


class TreeAndProofTests(unittest.TestCase):
    def test_single_leaf_root(self) -> None:
        tree = merkle.build_tree(42)
        self.assertEqual(tree.root, merkle.leaf_hash("", 42))
        self.assertEqual(tree.proofs[""], [])

    def test_empty_root_definition(self) -> None:
        self.assertEqual(
            merkle.EMPTY_ROOT, hashlib.sha256(b"").hexdigest()
        )

    def test_all_proofs_verify_roundtrip(self) -> None:
        tree = merkle.build_tree(DOC)
        entries = merkle.flatten(DOC)
        # 根可复现
        self.assertEqual(tree.root, merkle.build_tree(DOC).root)
        self.assertEqual(len(entries), len(tree.proofs))

        for path, value in entries:
            steps = [s.as_dict() for s in tree.proofs[path]]
            result = merkle.verify_inclusion(path, value, steps, tree.root)
            self.assertEqual(result, tree.root, msg=path)

    def test_odd_layer_duplicated_last(self) -> None:
        # tags 子树有 3 个叶子；构造一个恰好奇数叶的文档
        doc = {"k": [10, 20, 30]}
        tree = merkle.build_tree(doc)
        # 全部叶子证明必须验证通过
        for path, value in merkle.flatten(doc):
            steps = [s.as_dict() for s in tree.proofs[path]]
            self.assertEqual(
                merkle.verify_inclusion(path, value, steps, tree.root),
                tree.root,
            )
        # 手工确认 3 叶树结构
        h0 = merkle.leaf_hash("/k/0", 10)
        h1 = merkle.leaf_hash("/k/1", 20)
        h2 = merkle.leaf_hash("/k/2", 30)
        p01 = merkle.pair_hash(h0, h1)
        p22 = merkle.pair_hash(h2, h2)
        self.assertEqual(tree.root, merkle.pair_hash(p01, p22))

    def test_tampered_value_detected_at_leaf(self) -> None:
        tree = merkle.build_tree(DOC)
        steps = [s.as_dict() for s in tree.proofs["/age"]]
        # 值被改：第 0 步 node 立即不匹配（单步路径）
        with self.assertRaises(ServiceError) as ctx:
            merkle.verify_inclusion("/age", 31, steps, tree.root)
        self.assertIn(ctx.exception.code, {"PROOF_STEP_MISMATCH", "ROOT_MISMATCH"})

    def test_tampered_path_detected(self) -> None:
        tree = merkle.build_tree(DOC)
        steps = [s.as_dict() for s in tree.proofs["/age"]]
        with self.assertRaises(ServiceError) as ctx:
            merkle.verify_inclusion("/name", 30, steps, tree.root)
        self.assertIn(ctx.exception.code, {"PROOF_STEP_MISMATCH", "ROOT_MISMATCH"})

    def test_tampered_sibling_step_located(self) -> None:
        tree = merkle.build_tree(DOC)
        path = "/nested/x"
        steps = [dict(s) for s in (
            s.as_dict() for s in tree.proofs[path]
        )]
        self.assertTrue(steps)
        # 篡改第 0 步兄弟哈希
        bad = "0" * 64 if steps[0]["sibling"] != "0" * 64 else "1" * 64
        steps[0]["sibling"] = bad
        with self.assertRaises(ServiceError) as ctx:
            merkle.verify_inclusion(path, 1, steps, tree.root)
        self.assertEqual(ctx.exception.code, "PROOF_STEP_MISMATCH")
        self.assertEqual(ctx.exception.details["step"], 0)

    def test_tampered_root_detected(self) -> None:
        tree = merkle.build_tree(DOC)
        steps = [s.as_dict() for s in tree.proofs["/age"]]
        with self.assertRaises(ServiceError) as ctx:
            merkle.verify_inclusion("/age", 30, steps, "f" * 64)
        self.assertEqual(ctx.exception.code, "ROOT_MISMATCH")

    def test_malformed_step(self) -> None:
        tree = merkle.build_tree(DOC)
        good = [s.as_dict() for s in tree.proofs["/age"]]
        with self.assertRaises(ServiceError) as ctx:
            merkle.verify_inclusion("/age", 30, [{"side": "X"}], tree.root)
        self.assertEqual(ctx.exception.code, "MALFORMED_PROOF")
        self.assertEqual(ctx.exception.details["step"], 0)
        with self.assertRaises(ServiceError) as ctx2:
            merkle.verify_inclusion("/age", 30, good, "abc")
        self.assertEqual(ctx2.exception.code, "INVALID_ROOT")


class PointerTests(unittest.TestCase):
    def test_escape_roundtrip(self) -> None:
        for token in ["a/b", "a~b", "~", "/", "x~1y"]:
            self.assertEqual(
                jsonptr.parse("/" + jsonptr.escape(token)), [token]
            )

    def test_resolve_and_errors(self) -> None:
        self.assertEqual(jsonptr.resolve(DOC, "/tags/1"), "b")
        with self.assertRaises(ServiceError) as ctx:
            jsonptr.resolve(DOC, "/nope")
        self.assertEqual(ctx.exception.code, "POINTER_NOT_FOUND")
        self.assertEqual(ctx.exception.details["token_index"], 0)
        with self.assertRaises(ServiceError) as ctx:
            jsonptr.resolve(DOC, "/tags/9")
        self.assertEqual(ctx.exception.code, "POINTER_NOT_FOUND")
        with self.assertRaises(ServiceError) as ctx:
            jsonptr.resolve(DOC, "/age/x")
        self.assertEqual(ctx.exception.code, "POINTER_PARENT_SCALAR")
        with self.assertRaises(ServiceError) as ctx:
            jsonptr.resolve(DOC, "a")
        self.assertEqual(ctx.exception.code, "INVALID_POINTER_SYNTAX")
        with self.assertRaises(ServiceError) as ctx:
            jsonptr.resolve(DOC, "/a~2")
        self.assertEqual(ctx.exception.code, "INVALID_POINTER_SYNTAX")
        with self.assertRaises(ServiceError) as ctx:
            jsonptr.resolve(DOC, "/tags/01")
        self.assertEqual(ctx.exception.code, "POINTER_NOT_FOUND")

    def test_root_pointer(self) -> None:
        self.assertIs(jsonptr.resolve(DOC, ""), DOC)


if __name__ == "__main__":
    unittest.main()
