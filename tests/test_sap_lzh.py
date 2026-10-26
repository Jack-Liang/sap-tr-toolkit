#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sap_lzh 回环自测: 压缩 -> 解压 应精确还原原始数据。

不依赖任何样本包, 可在干净环境直接运行:

    python tests/test_sap_lzh.py          # 纯标准库断言
    python -m pytest tests/               # 也可用 pytest
"""

import os
import random
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sap_lzh  # noqa: E402


def _rand_bytes(n: int, seed: int) -> bytes:
    rng = random.Random(seed)
    return bytes(rng.getrandbits(8) for _ in range(n))


# 覆盖: 纯文本 / 高重复 / 全字节值 / 不可压缩随机 / 跨多个 16K 块的大块
SAMPLES = {
    "text": ("REPORT zdemo.\n" + "WRITE / 'hello sap'.\n" * 400).encode(),
    "repetitive": b"ABABABAB" * 5000,
    "binary": bytes(range(256)) * 300,
    "random": _rand_bytes(50000, 42),
    "large": b"x" * 20000 + _rand_bytes(30000, 7) + b"y" * 10000,
}


def _roundtrip(data: bytes, algorithm: int) -> None:
    _, _, packed = sap_lzh.compress(data, algorithm)
    status, _, plain = sap_lzh.decompress(packed, len(data))
    assert status == 1, "expected CS_END_OF_STREAM"
    assert plain == data, "roundtrip mismatch (%d bytes)" % len(data)


def test_lzh_roundtrip():
    for name, data in SAMPLES.items():
        _roundtrip(data, sap_lzh.ALG_LZH)


def test_lzc_roundtrip():
    for name, data in SAMPLES.items():
        _roundtrip(data, sap_lzh.ALG_LZC)


def test_record_parsing():
    """sap_src_unpack 的记录层: 4 字节头 + 0x2020 标记的 UTF-16LE 源码行。"""
    import sap_src_unpack

    payload = struct.pack("<H", sap_src_unpack.MARK_SOURCE) + "REPORT zdemo.".encode("utf-16-le")
    stream = b"\x00\x00" + struct.pack(">H", len(payload) + 4) + payload
    records = sap_src_unpack.parse_records(stream)
    assert len(records) == 1
    assert records[0].kind == "source"
    assert "REPORT zdemo." in records[0].text


if __name__ == "__main__":
    test_lzh_roundtrip()
    test_lzc_roundtrip()
    test_record_parsing()
    print("OK: %d 个样本 x LZH/LZC 回环 + 记录解析全部通过" % len(SAMPLES))
