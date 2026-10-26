#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端测试: 合成一个 SAP 源码导出包, 走完整解包流程。

按真实结构构造 R 体 (ASCII 文本头 + 16384 字节分块的 LZH 压缩记录流),
连同 K 体和干扰成员 README.txt 打成 zip, 验证:

  - 后缀不是 .ED1 的成员 (如 R123456.dat) 能被正确识别
  - README.txt 之类成员不会被误当成 R 体 (旧版 startswith("R") 的坑)
  - 单个 R 体文件 (任意后缀, 非 zip) 可直接喂给命令行
  - 包内格式令牌随系统命名变化 (ED1K/TD1K 清单行、ED1/TD1 时间戳行),
    解析不写死令牌; 对象行的类型与名字连写/隔空格两种形态都能解析

运行: python tests/test_unpack_end2end.py  或  python -m pytest tests/
"""

import os
import struct
import subprocess
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import sap_lzh            # noqa: E402
import sap_src_unpack    # noqa: E402

BLOCK_SIZE = 16384   # 与真实包一致: 每块解出 16384 字节


def _record(payload: bytes) -> bytes:
    assert len(payload) + 4 <= 0xFFFF
    return b"\x00\x00" + struct.pack(">H", len(payload) + 4) + payload


def _src_line(text: str) -> bytes:
    return _record(struct.pack("<H", sap_src_unpack.MARK_SOURCE)
                   + text.encode("utf-16-le"))


def _hdr_line(text: str) -> bytes:
    return _record(struct.pack("<H", sap_src_unpack.MARK_HEADER)
                   + text.encode("utf-16-le"))


def _build_r_body() -> bytes:
    stream = bytearray()
    # 两种格式令牌的清单行 (令牌随系统命名变化, 解析不能写死);
    # 对象行同时覆盖 "类型+名字连写" 与 "类型 名字隔空格" 两种形态
    stream += _record(b"ED1K123456          000002LIMUFUNCZDEMO_E2E")
    stream += _record(b"TD1K900048          000001R3TRCLAS ZDEMO_CL")
    stream += _hdr_line("XSD$ IS DEVUSER 20261026 ZDEMO_E2E")
    stream += _src_line("REPORT zdemo_e2e.")
    stream += _src_line("WRITE / 'hello'.")
    stream += _src_line("FORM frm_demo.")
    stream += _src_line("ENDFORM.")
    # 补齐到 > 16384 字节, 保证首块长度字段 = 0x4000 (首字节 0x00),
    # 与真实包一致, 避免 ASCII 文本头扫描吞进块头
    i = 0
    while len(stream) <= BLOCK_SIZE:
        stream += _src_line("* filler line %03d" % i)
        i += 1

    body = bytearray(b"R123456 ED1 synthetic")   # ASCII 文本头
    for i in range(0, len(stream), BLOCK_SIZE):
        chunk = bytes(stream[i:i + BLOCK_SIZE])
        body += sap_lzh.compress(chunk, sap_lzh.ALG_LZH)[2]
    return bytes(body)


K_TEXT = (
    "DEVUSER        K EQ1        1   0   3\n"
    "ED1 f 0000 20261026162654 S4DDEV       devadm\n"
    "TD1 e 0000 20260923165212 TS4QAS01       td1adm\n"
)


def _make_zip(path: str, ext: str) -> None:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("README.txt", "not an R body")
        z.writestr(f"R123456.{ext}", _build_r_body())
        z.writestr(f"K123456.{ext}", K_TEXT)


def test_extract_with_arbitrary_extension():
    with tempfile.TemporaryDirectory() as td:
        zpath = os.path.join(td, "demo.zip")
        _make_zip(zpath, "dat")
        out = os.path.join(td, "out")
        rc = sap_src_unpack.extract(zpath, out)
        assert rc == 0, "非 .ED1 后缀成员应能正常解包"
        src = open(os.path.join(out, "ZDEMO_E2E.abap"), encoding="utf-8").read()
        assert "REPORT zdemo_e2e." in src and "ENDFORM." in src
        merged = open(os.path.join(out, "ALL_SOURCES.abap"), encoding="utf-8").read()
        assert "frm_demo" in merged
        meta = open(os.path.join(out, "metadata.txt"), encoding="utf-8").read()
        assert "ZDEMO_E2E" in meta and "S4DDEV" in meta
        assert "ZDEMO_CL" in meta and "TS4QAS01" in meta   # 非默认令牌同样解析


def test_extract_with_ed1_extension():
    with tempfile.TemporaryDirectory() as td:
        zpath = os.path.join(td, "demo.zip")
        _make_zip(zpath, "ED1")
        rc = sap_src_unpack.extract(zpath, os.path.join(td, "out"))
        assert rc == 0


def test_single_r_file_any_extension():
    with tempfile.TemporaryDirectory() as td:
        rpath = os.path.join(td, "R123456.bin")
        with open(rpath, "wb") as f:
            f.write(_build_r_body())
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cli = os.path.join(root, "sap_src_unpack.py")
        proc = subprocess.run([sys.executable, cli, rpath, "--list"],
                              capture_output=True, text=True)
        assert proc.returncode == 0, proc.stderr
        assert "ZDEMO_E2E" in proc.stdout


if __name__ == "__main__":
    test_extract_with_arbitrary_extension()
    test_extract_with_ed1_extension()
    test_single_r_file_any_extension()
    print("OK: 源码包端到端 (任意后缀成员 / 干扰成员 / 单文件 / 令牌泛化) 全部通过")
