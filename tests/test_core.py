# -*- coding: utf-8 -*-
"""sec-analyzer 内核单元测试：不依赖 Flask / 网络，直接 python -m unittest discover。"""
import os
import tempfile
import unittest
from unittest import mock

import config
import core
import db


def make_alert(rule="SQL_INJECTION", payload="' OR 1=1--", host="api-1", path="/login",
               ip="1.2.3.4", t="2026-03-01 10:00:00"):
    return {"rule_id": rule, "payload": payload, "host": host,
            "path_template": path, "src_ip": ip, "event_time": t,
            "method": "POST", "alert_id": 1}


class SecurityTest(unittest.TestCase):
    def test_password_hashed_and_salted(self):
        h1, h2 = db.hash_password("secret"), db.hash_password("secret")
        self.assertNotEqual(h1, h2, "相同口令应产生不同哈希（随机盐）")
        self.assertNotIn("secret", h1)
        self.assertTrue(db.verify_password("secret", h1))
        self.assertFalse(db.verify_password("wrong", h1))

    def test_api_key_sealed(self):
        key = "sk-abcdef123456"
        sealed = db.seal_api_key(key)
        self.assertNotIn(key, sealed)
        self.assertEqual(db.unseal_api_key(sealed), key)
        self.assertEqual(db.unseal_api_key("legacy-plain"), "legacy-plain")  # 向后兼容


class CacheTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w")
        self.tmp.write("{}")
        self.tmp.close()
        self.orig = core.CACHE_FILE
        core.CACHE_FILE = self.tmp.name

    def tearDown(self):
        core.CACHE_FILE = self.orig
        os.unlink(self.tmp.name)

    def test_cache_key_differs_by_perspective(self):
        a = make_alert()
        self.assertNotEqual(core.cache_key(a, "signature"), core.cache_key(a, "business"),
                            "不同视角必须对应不同缓存键，否则投票会退化")

    def test_judge_uses_cache(self):
        a = make_alert()
        core.write_cache(a, {"is_false_positive": True, "reason": "cached"}, "signature")
        r = core.judge_alert(a, perspective="signature")
        self.assertTrue(r["from_cache"])
        self.assertTrue(r["is_false_positive"])


class ClusterTest(unittest.TestCase):
    def test_jaccard(self):
        self.assertEqual(core.jaccard_similarity("ab", "ab"), 1.0)
        self.assertEqual(core.jaccard_similarity("ab", "cd"), 0.0)

    def test_complete_linkage_order_insensitive(self):
        # 三条 payload，A/B 相似，C 不同；complete-linkage 不应把 C 拉进同一簇
        a = make_alert(payload="' OR 1=1--")
        b = make_alert(payload="' OR 2=2--")
        c = make_alert(payload="hello world normal request")
        g1 = core.cluster_stage2_semantic([a, b, c], threshold=0.5, strategy="complete")
        g2 = core.cluster_stage2_semantic([c, b, a], threshold=0.5, strategy="complete")
        self.assertEqual(len(g1), len(g2), "聚类结果数量不应随输入顺序变化")


class VotingTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w")
        self.tmp.write("{}")
        self.tmp.close()
        self.orig = core.CACHE_FILE
        core.CACHE_FILE = self.tmp.name

    def tearDown(self):
        core.CACHE_FILE = self.orig
        os.unlink(self.tmp.name)

    def test_analyze_uses_perspectives(self):
        alerts = [make_alert() for _ in range(4)]
        result = core.analyze(alerts, use_llm=False)
        vc = result["vote_config"]
        self.assertEqual(vc["rounds"], 2)
        self.assertEqual(vc["perspectives"], ["signature", "business"])
        self.assertEqual(vc["consensus_ratio"], 0.75)
        # 两视角 × 每视角独立缓存 => 缓存条目数 >= 视角数
        self.assertGreaterEqual(result["cache_hit"], 2)


if __name__ == "__main__":
    unittest.main()
