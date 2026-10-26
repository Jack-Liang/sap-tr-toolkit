#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sap_src_unpack — 解包 SAP GUI「SE38 → 程序下载 / Goto → 下载」导出的源码包。

产出可读的 ABAP 源码 + 对象清单 + 元数据。

用法:
    python sap_src_unpack.py <file.zip|R体文件> [-o OUTDIR]
    python sap_src_unpack.py <file.zip> --list
    python sap_src_unpack.py <file.zip> --stdout

包结构 (逆向自实际样本)。注意: 成员扩展名与包内格式令牌都随系统命名而变化
(不是稳定标识), 一律按 "K/R + 数字" 的命名形态和内容结构识别, 不写死后缀/令牌:

  <NAME>.zip
    ├── K<id>.<ext>  对象头(Kopf): 程序名、属性、时间戳、依赖
    └── R<id>.<ext>  对象体(Rumpf): 文本头 + 若干 LZH 压缩块

R 体解压后是一串「记录」, 每条记录:
    00 00 <len:u16be> <payload:len-4 bytes>
  payload 可能是:
    - ASCII 元数据行  (如 " *dbtabpos:1", "<格式令牌>K<id>  ...")
    - UTF-16LE 源码行 (前面带 2 字节标记, 0x2020 = 源码, 0x2046 = 对象头)
  源码行固定 255 字符宽, 补空格。

依赖: sap_lzh.py (同目录, pysapcompress 移植版
https://github.com/CoreSecurity/pysap , 实现 SAP LZH/LZC)。
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import zipfile
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sap_lzh  # noqa: E402  (本地模块, 需先加 sys.path)

MAGIC = b"\x1f\x9d"

# UTF-16LE 行首 2 字节标记 -> 语义
MARK_SOURCE = 0x2020   # 源码行
MARK_HEADER = 0x2046   # 对象头 (XSD$ 记录)
MARK_OTHER = 0x2E00    # 其它

LINE_WIDTH = 255        # SAP 源码行固定宽度 (字符)


# ---------------------------------------------------------------------------
# 1. LZH 解压
# ---------------------------------------------------------------------------

def decompress_r_body(raw: bytes) -> bytes:
    """把 R 体的压缩块序列解成明文记录流。

    每个块: 8 字节 SAP 头 (magic 1f 9d 在 offset 5) + LZH 数据。
    用 reader.bytes_read 精确推进到下一块, 避免误判边界。
    """
    out = bytearray()
    pos = 0
    n = len(raw)
    while pos < n:
        # 找下一个 magic (5 字节头偏移)
        idx = raw.find(MAGIC, pos)
        if idx < 0:
            break
        start = idx - 5
        if start < 0:
            break
        try:
            dec = sap_lzh._LZHDecompress(raw[start:])
            blob = dec.decompress()
        except Exception:
            # 该 magic 可能是压缩流里的巧合字节, 跳过继续找
            pos = idx + 1
            continue
        consumed = dec._reader.bytes_read
        if consumed <= 0:
            pos = idx + 1
            continue
        out += blob
        pos = start + consumed
    return bytes(out)


# ---------------------------------------------------------------------------
# 2. 记录流解析
# ---------------------------------------------------------------------------

@dataclass
class Record:
    offset: int
    length: int
    payload: bytes
    kind: str = "raw"        # raw | ascii | source | header
    text: str = ""

    @property
    def is_code(self) -> bool:
        return self.kind == "source"


def _odd_zero_ratio(payload: bytes) -> float:
    """UTF-16LE 判据: 奇数位字节绝大多数应为 0 (ASCII 字符的高位)。

    导出包里有些 0x2020 开头的记录其实是 ASCII 表格数据, 误按 UTF-16 解会
    变成乱码。这个比例能把两者可靠区分开。
    """
    body = payload[2:]
    if not body:
        return 0.0
    odd = body[1::2]
    return sum(1 for b in odd if b == 0) / len(odd)


def _decode_payload(payload: bytes) -> tuple[str, str]:
    """判定 payload 是 ASCII 元数据还是 UTF-16 源码, 返回 (kind, text)。"""
    if not payload:
        return "raw", ""

    # UTF-16LE 源码行: 前 2 字节是标记, 之后是 UTF-16LE 文本
    if len(payload) >= 4 and len(payload) % 2 == 0:
        mark = payload[0] | (payload[1] << 8)
        if mark in (MARK_SOURCE, MARK_HEADER) and _odd_zero_ratio(payload) >= 0.9:
            try:
                text = payload[2:].decode("utf-16-le")
            except UnicodeDecodeError:
                text = None
            if text is not None:
                kind = "source" if mark == MARK_SOURCE else "header"
                return kind, text

    # ASCII 元数据
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        text = payload.decode("latin-1")
    if all(c == "\x00" or (32 <= ord(c) < 127) for c in text):
        return "ascii", text
    return "raw", text


def parse_records(stream: bytes) -> list[Record]:
    """把明文流切成记录列表。"""
    records: list[Record] = []
    pos = 0
    n = len(stream)
    while pos + 4 <= n:
        if stream[pos] != 0 or stream[pos + 1] != 0:
            # 不是记录头, 尝试重新同步
            nxt = stream.find(b"\x00\x00", pos + 1)
            if nxt < 0 or nxt - pos > 4:
                break
            pos = nxt
            continue
        length = (stream[pos + 2] << 8) | stream[pos + 3]
        if length < 4 or pos + length > n:
            break
        payload = stream[pos + 4: pos + length]
        kind, text = _decode_payload(payload)
        records.append(Record(pos, length, payload, kind, text))
        pos += length
    return records


# ---------------------------------------------------------------------------
# 3. 源码行整理
# ---------------------------------------------------------------------------

# 行首标记: 源码行 payload 的前 2 字节是 0x2020, 文本从 [2:] 开始。
# 但部分行 (如 "XXSD$" 头) 标记不同, 统一在这里剥离。

def strip_line_prefix(text: str) -> str:
    """去掉源码行文本里残留的标记字符。"""
    if text and text[0] in (" ", " "):
        text = text[1:]
    return text.rstrip()


def collect_source_lines(records: list[Record]) -> list[str]:
    """把源码类记录还原成 ABAP 文本行。

    导出包的记录流里混着三类东西:
      - 真正的 ABAP 源码行 (UTF-16LE, 固定 255 字符宽)
      - 对象清单元数据行 (UTF-16LE, 但内容是清单, 非代码)
      - ASCII 表格数据 (属于 R3TR 属性表, 不是代码)

    关键结构: 源码永远出现在 "header" 记录 (0x2046, XSD$ 头) 之后的
    连续区段里; header 之前的 UTF-16 内容都是对象清单/元数据。
    因此这里按 header 边界切段, 只取 header 之后的源码。
    """
    lines: list[str] = []
    known = collect_known_object_names(records)
    in_code = False
    for rec in records:
        if rec.kind == "header":
            # 新对象的源码区段开始
            in_code = True
            body = rec.payload[2:].decode("utf-16-le", errors="replace")
            lines.append("*" + strip_line_prefix(body))
            continue
        if rec.kind != "source":
            # ASCII 表格数据只作分隔, 不影响 code 区段
            continue
        body = strip_line_prefix(rec.payload[2:].decode("utf-16-le", errors="replace"))
        if not in_code:
            continue
        # header 区段内仍可能出现对象清单行 (导出包交错写入)
        if is_pack_meta_line(body, known):
            continue
        lines.append(body)
    return lines


def is_pack_meta_line(line: str, known_objs: set[str] | None = None) -> bool:
    """判断是否为导出包插入的元数据行 (而非 ABAP 代码)。

    对象清单行有确定形态:
        <对象名>  <大段空白>  <字段>  <空白>  <值>
    且第一个 token 一定是已知的对象名 (FUGR.../函数名/类名/include 名)。

    判据必须是"白名单式"的 —— 只在第一个 token 命中已知对象名时才判为元数据,
    否则会误杀像 "OTHERS = 3." 这样的真实代码行。
    """
    st = line.strip()
    if not st:
        return False

    # 对象清单行: "<格式令牌>K<id> ...", 令牌随系统命名变化, 不能写死
    if re.match(r"^[A-Z]{2,4}1K\d", st):
        return True

    if not known_objs:
        return False

    # 取第一个 token
    tok = st.split()[0] if st.split() else ""
    # 去掉清单行里的类型前缀 (CI/CU/CV/FL/PR/SV + 对象名)
    for pref in ("CI", "CU", "CV", "FL", "PR", "SV"):
        if tok.startswith(pref) and tok[len(pref):] in known_objs:
            tok = tok[len(pref):]
            break
    if tok not in known_objs:
        return False

    # 必须是 "名 + 大段空白 + 字段" 的表格形态
    return bool(re.match(r"^[A-Z][A-Z0-9_/]{3,}\s{5,}\S", st))


def collect_known_object_names(records: list[Record]) -> set[str]:
    """从清单行里收集已知对象名, 用于识别元数据行。

    只接受真正的清单形态: 大写名 + 大段空白 + 后续字段。
    (像 "OTHERS         = 3." 这种代码行会因为含 '=' 被排除)
    """
    names: set[str] = set()
    for rec in records:
        if rec.kind != "source":
            continue
        body = rec.payload[2:].decode("utf-16-le", errors="replace")
        st = body.strip()
        m = re.match(r"^([A-Z][A-Z0-9_/]{3,})\s{5,}(\S.*)$", st)
        if not m:
            continue
        rest = m.group(2)
        # 清单行的第二段是另一个标识符 (类型/字段名), 不含 '=' 也不含小写单词
        if "=" in rest:
            continue
        if re.search(r"\b[a-z]{4,}\b", rest):
            continue
        names.add(m.group(1))
    return names


# ---------------------------------------------------------------------------
# 4. 对象切分
# ---------------------------------------------------------------------------

@dataclass
class SapObject:
    obj_type: str = ""       # FUGR / PROG / INCLUDE ...
    name: str = ""           # ZDEMO_IF_SBSJ
    kind: str = "unknown"    # function-module / program / include
    lines: list[str] = field(default_factory=list)
    attrs: dict = field(default_factory=dict)
    owner: str = ""          # 所属函数组 / 程序


# 源码里出现 "FUNCTION zdemo_if_sbsj." / "REPORT x" / "INCLUDE y ." 的位置即为对象边界
RE_FM_START = re.compile(r"^\s*FUNCTION\s+([A-Za-z0-9_/]+)\s*\.", re.IGNORECASE)
RE_REPORT = re.compile(r"^\s*REPORT\s+([A-Za-z0-9_/]+)", re.IGNORECASE)
RE_INCLUDE = re.compile(r"^\s*INCLUDE\s+([A-Za-z0-9_]+)\s*\.", re.IGNORECASE)

# 对象名清单行, 形如:
#   "LZDEMOGIF15_SWD01                       1Include LZDEMOGIF15_SWD01"
#   "FUGRZDEMOGIF15_SW                           FUNCZDEMO_IF_SBRQ"
RE_OBJLINE = re.compile(r"^([A-Z][A-Z0-9_/]{2,})\s{2,}(\d+)?\s*([A-Za-z]+\s*)?(\S+)?\s*$")
RE_KINDWORD = re.compile(r"\b(Include|Function|Program|Report|Class|Method|Interface)\b", re.IGNORECASE)


def _classify_block(lines: list[str]) -> tuple[str, str]:
    """从一个对象块里判断 (kind, name)。"""
    for line in lines:
        s = line.strip()
        m = RE_FM_START.match(line)
        if m:
            return "function-module", m.group(1).upper()
        m = RE_REPORT.match(line)
        if m:
            return "program", m.group(1).upper()
        m = RE_INCLUDE.match(line)
        if m:
            return "include", m.group(1).upper()
    # 找 "FUNCTION $$UNIT$$ X" 这种接口声明
    for line in lines:
        m = re.search(r"FUNCTION\s+\$\$UNIT\$\$\s+(\S+)", line, re.IGNORECASE)
        if m:
            return "function-module", m.group(1).upper()
    # 类定义
    for line in lines:
        m = re.match(r"^\s*CLASS\s+(\S+)\s+DEFINITION", line, re.IGNORECASE)
        if m:
            return "class", m.group(1).upper()
    return "unknown", ""


RE_BANNER = re.compile(
    r"^\*{10,}$"                        # *** 分隔线
    r"|^\*$"                            # 空头记录伪影 (孤立的 *)
    r"|^\*\s*X?X?SD\$"                  # XSD$ / SD$ 对象头横幅及其变体
    r"|^\*[A-Z][A-Z0-9_/]{3,}\s{5,}\S"  # 属性注册表行 (大写对象名 + 宽空白 + 字段)
    r"|^\*\s{5,}\d"                     # 注册表续行 ( * + 宽空白 + 数字开头)
    r"|^_{3,}$"                         # 属性表里的下划线分隔条
)
RE_BANNER_TEXT = re.compile(
    r"^\*\s+(THIS FILE IS GENERATED BY THE FUNCTION LIBRARY"
    r"|NEVER CHANGE IT MANUALLY)",
    re.IGNORECASE,
)


def strip_banner(lines: list[str]) -> list[str]:
    """去掉 SAP 导出包自动生成的横幅与表格伪影 (对象头、*** 分隔线、提示语等)。

    这些是 SAP 生成的文件头/属性表残片, 不是开发者写的代码, 但保留着也无害 ——
    默认保留, 仅在 --no-banner 时剔除。部分导出类型的包里同类伪影更多
    (孤立 * 行、属性注册表行), 同样只在此开关下清理。
    """
    out = []
    for l in lines:
        st = l.strip()
        if RE_BANNER.match(st) or RE_BANNER_TEXT.match(st):
            continue
        if "\x00" in st:   # NUL 字节: 解码出的表格残片, 不可能是真源码
            continue
        out.append(l)
    return out


def split_objects(lines: list[str]) -> list[SapObject]:
    """按 FUNCTION / REPORT / INCLUDE / CLASS 边界把源码切成多个对象。

    导出包里一个物理块 (header 记录) 可能含多个逻辑对象, 例如函数组里
    先是 "$$UNIT$$" 接口声明, 随后才是真正实现。
    """
    objs: list[SapObject] = []
    cur = SapObject(kind="unknown")
    cur.lines = []
    seen_kind = set()

    for line in lines:
        s = line.strip()
        if not s:
            continue

        m = RE_INCLUDE.match(line)
        if m:
            if cur.lines:
                objs.append(cur)
            cur = SapObject(kind="include", name=m.group(1).upper())
            cur.lines = [line]
            seen_kind = {"include"}
            continue

        m = RE_FM_START.match(line)
        if m:
            name = m.group(1).upper()
            if cur.lines and (cur.kind != "function-module" or cur.name != name):
                objs.append(cur)
                cur = SapObject(kind="function-module", name=name)
            else:
                cur.kind = "function-module"
                cur.name = name
            cur.lines.append(line)
            seen_kind = {"function-module"}
            continue

        m = RE_REPORT.match(line)
        if m:
            if cur.lines:
                objs.append(cur)
            cur = SapObject(kind="program", name=m.group(1).upper())
            cur.lines = [line]
            seen_kind = {"program"}
            continue

        # FUNCTION $$UNIT$$ <name>  —— 函数接口声明 (导出包生成)
        m = re.match(r"^\s*FUNCTION\s+\$\$UNIT\$\$\s+(\S+)", line, re.IGNORECASE)
        if m:
            if cur.lines:
                objs.append(cur)
            cur = SapObject(kind="function-interface", name=m.group(1).upper())
            cur.lines = [line]
            seen_kind = {"function-interface"}
            continue

        # CLASS ... DEFINITION 开启一个新类
        m = re.match(r"^\s*CLASS\s+(\S+)\s+DEFINITION", line, re.IGNORECASE)
        if m and ("class" not in seen_kind):
            if cur.lines:
                objs.append(cur)
            cur = SapObject(kind="class", name=m.group(1).upper())
            cur.lines = [line]
            seen_kind = {"class"}
            continue

        cur.lines.append(line)

    if cur.lines:
        objs.append(cur)
    return objs


# ---------------------------------------------------------------------------
# 5. 元数据
# ---------------------------------------------------------------------------

# 对象清单行: "<格式令牌>K<id>  <key><value>"。格式令牌随系统命名变化
# (实测有 ED1K / TD1K), 不能写死
RE_OBJLIST = re.compile(r"^([A-Z]{2,4}1)K(\d+)\s+(\S.*)$")


def parse_metadata(records: list[Record], k_text: str) -> dict:
    """从 K 头 + 对象清单记录里抽元数据。"""
    meta: dict = {"sap_components": [], "objects": []}

    # K 文件: "DEVUSER  K EQ1 ..." / "<格式令牌> f 0000 20261026162654 S4DDEV devadm"
    # 时间戳行的令牌同样随系统命名变化 (实测 ED1 / TD1), 按形态匹配
    for line in k_text.splitlines():
        line = line.rstrip()
        if not line:
            continue
        parts = line.split()
        m_ts = re.match(r"^[A-Z]{2,4}1\s+(\S+)\s+\d+\s+(\d{14})\s+(\S+)\s+(\S*)$", line)
        if m_ts:
            meta.setdefault("timestamps", []).append({
                "action": m_ts.group(1), "date": m_ts.group(2),
                "system": m_ts.group(3), "user": m_ts.group(4),
            })
        elif parts[0] == "EQ1":
            continue
        elif len(parts) > 1 and parts[1] in ("K", "R"):
            meta["program_name"] = parts[0]
            meta["object_id"] = parts[0]
        elif line.startswith("*client:"):
            meta["client"] = line.split(":", 1)[1].strip()
        elif line.startswith("*Source System"):
            meta["source_system"] = line.split("=", 1)[-1].strip()

    # 对象清单记录: "<令牌>K<id>  <key><value>" (令牌随系统变化, 如 ED1K/TD1K)
    #   形如 000002LIMUFUNCZDEMO_IF_SBRQ  -> 类型 LIMU / 子类 FUNC / 名字
    #   形如 000002SAPCOMPONENT   BSNAGT,200,0008
    #   形如 000003R3TRFUGRZDEMOGIF15_SW
    for rec in records:
        if rec.kind not in ("source", "ascii"):
            continue
        for raw in rec.text.split("\n"):
            line = raw.rstrip()
            m = RE_OBJLIST.match(line)
            if not m:
                continue
            rest = m.group(3).strip()
            if not rest:
                continue

            m2 = re.match(r"^(\d+)(SAPCOMPONENT)\s+(\S+)$", rest)
            if m2:
                meta["sap_components"].append(m2.group(3))
                continue

            # 对象行: "R3TR"/"LIMU" + 子类型 + 名字。子类型与名字可能连写
            # (如 LIMUFUNCZDEMO_E2E) 也可能隔空格 (如 "R3TRCLAS ZCL_..."),
            # 名字后还可能跟其它列。子类型用 SAP 标准对象类型词表界定
            # (这部分是稳定词表, 不随系统命名变化), 名字只取一个 token
            m2 = re.match(
                r"^(\d+)(R3TR|LIMU)(DOMA|DTEL|FUGR|PROG|TABL|VIEW|INTF|CLAS|"
                r"TTYP|ENQU|SHLP|MSAG|TRAN|SUSO|SSFO|SSST|XSLT|WDYA|WAPA|"
                r"FUNC|REPS|METH|INCL|CU|CV|CI)\s*(\S+)", rest)
            if m2:
                meta["objects"].append({
                    "type": m2.group(2) + m2.group(3),
                    "name": m2.group(4).strip(),
                })
                continue

            m2 = re.match(r"^(\d+)([A-Z]{2,})\s*(.*)$", rest)
            if m2:
                meta.setdefault("attributes", []).append(rest)
    return meta


# ---------------------------------------------------------------------------
# 6. 主流程
# ---------------------------------------------------------------------------

# 包内成员识别: SAP 导出包里成员是 K<id>.<ext> / R<id>.<ext>。
# 扩展名随系统命名变化, 不作为识别依据; 只按 "K/R + 数字" 的命名形态识别。
RE_MEMBER_R = re.compile(r"^R\d+", re.IGNORECASE)
RE_MEMBER_K = re.compile(r"^K\d+", re.IGNORECASE)


def find_member(names: list[str], pattern: re.Pattern) -> str | None:
    """按命名形态在 zip 成员里找 K/R 体文件 (避免把 README.txt 等误当 R 体)。"""
    for n in names:
        if pattern.match(os.path.basename(n)):
            return n
    return None


def extract(zip_path: str, outdir: str | None, list_only: bool = False,
            no_banner: bool = False) -> int:
    base = os.path.splitext(os.path.basename(zip_path))[0]
    outdir = outdir or os.path.join(os.getcwd(), "sap_src_" + base)

    with zipfile.ZipFile(zip_path) as z:
        names = z.namelist()
        r_name = find_member(names, RE_MEMBER_R)
        k_name = find_member(names, RE_MEMBER_K)
        if not r_name:
            print(f"[!] 找不到 R 体文件 (R<数字>.*), 包内文件: {names}", file=sys.stderr)
            return 2
        r_raw = z.read(r_name)
        k_text = z.read(k_name).decode("latin-1") if k_name else ""

    # R 体: 文本头 + 压缩块
    head_end = 0
    while head_end < len(r_raw) and 32 <= r_raw[head_end] < 127:
        head_end += 1
    r_header = r_raw[:head_end].decode("latin-1").strip()
    r_body = r_raw[head_end:]

    stream = decompress_r_body(r_body)
    if not stream:
        print("[!] LZH 解压失败, 未能取得内容", file=sys.stderr)
        return 3

    records = parse_records(stream)
    lines = collect_source_lines(records)
    objs = split_objects(lines)
    meta = parse_metadata(records, k_text)

    # ---- 打印清单 ----
    print("=" * 72)
    print(f"SAP 源码包: {os.path.basename(zip_path)}")
    print(f"  R 体头部   : {r_header}")
    print(f"  记录数     : {len(records)}")
    print(f"  明文字节   : {len(stream)}")
    if "program_name" in meta:
        print(f"  程序名     : {meta['program_name']}")
    for k in ("source_system", "client"):
        if k in meta:
            print(f"  {k:<11}: {meta[k]}")
    for ts in meta.get("timestamps", []):
        print(f"  时间戳     : {ts['action']} {ts['date']} @ {ts['system']} ({ts['user']})")
    print("-" * 72)
    print("对象清单:")
    seen = set()
    for o in meta.get("objects", []):
        key = (o["type"], o["name"])
        if key in seen:
            continue
        seen.add(key)
        print(f"  {o['type']:<10} {o['name']}")
    print("-" * 72)
    print("源码对象:")
    for o in objs:
        if o.kind == "header":
            continue
        print(f"  {o.kind:<18} {o.name:<28} {len(o.lines):>5} 行")
    print("=" * 72)

    if list_only:
        return 0

    # ---- 落盘 ----
    os.makedirs(outdir, exist_ok=True)
    written = []

    idx = 0
    used: set[str] = set()
    for o in objs:
        if o.kind == "header":
            continue
        idx += 1
        base = o.name or f"object{idx}"
        # 同名对象 (接口声明 + 实现) 加后缀区分
        suffix = ""
        if base in used:
            n = 2
            while f"{base}_{n}" in used:
                n += 1
            suffix = f"_{n}"
        fname = f"{base}{suffix}.abap"
        used.add(base + suffix)
        path = os.path.join(outdir, fname)
        body = "\n".join(strip_banner(o.lines) if no_banner else o.lines)
        with open(path, "w", encoding="utf-8") as f:
            f.write(body + "\n")
        written.append((fname, len(o.lines)))

    # 合并版 (方便整体浏览/grep)
    merged = os.path.join(outdir, "ALL_SOURCES.abap")
    with open(merged, "w", encoding="utf-8") as f:
        f.write("*" + "=" * 74 + "\n")
        f.write("* SAP 源码包解包合并源码\n")
        f.write("*" + "=" * 74 + "\n\n")
        for o in objs:
            if o.kind == "header":
                continue
            f.write("*" + "-" * 74 + f"\n* {o.kind} : {o.name}\n")
            f.write("*" + "-" * 74 + "\n")
            f.write("\n".join(o.lines) + "\n\n")
    written.append(("ALL_SOURCES.abap", len(lines)))

    # 元数据
    meta_path = os.path.join(outdir, "metadata.txt")
    with open(meta_path, "w", encoding="utf-8") as f:
        f.write(f"# SAP 源码包元数据\n")
        f.write(f"包文件: {os.path.basename(zip_path)}\n")
        f.write(f"R 头: {r_header}\n")
        for k, v in meta.items():
            if k in ("sap_components", "objects", "timestamps"):
                continue
            f.write(f"{k}: {v}\n")
        f.write("\n# 时间戳\n")
        for ts in meta.get("timestamps", []):
            f.write(f"{ts}\n")
        f.write("\n# 对象清单\n")
        for o in meta.get("objects", []):
            f.write(f"{o['type']:<12} {o['name']}\n")
        f.write(f"\n# SAPCOMPONENT ({len(meta['sap_components'])})\n")
        for c in meta["sap_components"]:
            f.write(f"{c}\n")
    written.append(("metadata.txt", 0))

    print(f"输出目录: {outdir}")
    for fn, cnt in written:
        print(f"  {fn:<32} {cnt:>5} 行" if cnt else f"  {fn:<32}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description="解包 SAP GUI 导出的源码包 (SE38 程序下载) 为可读 ABAP",
    )
    ap.add_argument("path", help="*.zip 包, 或单个 R 体文件 (任意后缀)")
    ap.add_argument("-o", "--outdir", help="输出目录 (默认 ./sap_src_<包名>)")
    ap.add_argument("--list", action="store_true", help="只打印清单, 不落盘")
    ap.add_argument("--no-banner", action="store_true",
                    help="去掉 SAP 自动生成的横幅 (XSD$ 头 / *** 分隔线)")
    ap.add_argument("--stdout", action="store_true", help="合并源码打到标准输出")
    args = ap.parse_args()

    path = args.path
    if not os.path.isfile(path):
        print(f"[!] 文件不存在: {path}", file=sys.stderr)
        return 2
    if not zipfile.is_zipfile(path):
        # 不是 zip: 当作单个 R 体文件 (任意后缀), 造一个临时 zip 视图。
        # 文件名不符合 R<数字> 形态时, 强制按 R 体处理。
        import tempfile
        arcname = os.path.basename(path)
        if not RE_MEMBER_R.match(arcname):
            arcname = "R000000." + (arcname.rsplit(".", 1)[-1] if "." in arcname else "DAT")
        tmp = tempfile.NamedTemporaryFile(suffix=".zip", delete=False)
        with zipfile.ZipFile(tmp, "w") as z:
            z.write(path, arcname)
        tmp.close()
        path = tmp.name

    rc = extract(path, args.outdir, args.list, args.no_banner)
    if rc == 0 and args.stdout:
        base = os.path.splitext(os.path.basename(args.path))[0]
        d = args.outdir or os.path.join(os.getcwd(), "sap_src_" + base)
        p = os.path.join(d, "ALL_SOURCES.abap")
        if os.path.exists(p):
            sys.stdout.write(open(p, encoding="utf-8").read())
    return rc


if __name__ == "__main__":
    sys.exit(main())
