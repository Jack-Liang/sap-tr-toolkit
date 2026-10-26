# sap-tr-toolkit

> SAP Transport Request toolkit — download/upload transport requests with the
> bundled ABAP program, and unpack SE38-exported SAP source packages into
> readable ABAP with the Python CLI.

SAP 传输请求（Transport Request，TR）工具集，两个组件：

| 组件 | 说明 |
|---|---|
| `abap/ZUD.abap` | ABAP 报表程序：传输请求下载成 ZIP / 上传回服务器并触发导入（见第 8 节） |
| `sap_src_unpack.py` | Python 命令行：解包 SE38 导出的源码包为可读 ABAP 文件（见第 1 节起） |

## 仓库结构

```
.
├── sap_src_unpack.py   # 源码包解包主程序（命令行）
├── sap_lzh.py           # SAP LZH/LZC 压缩算法实现（GPL-2.0，见「许可证」）
├── abap/
│   ├── ZUD.abap         # 传输请求(TR) 下载/上传 ABAP 程序（见第 8 节）
│   └── LICENSE-ZUD      # ZUD 的 MIT 许可（上游 furkancosgun）
└── tests/
    ├── test_sap_lzh.py      # LZH/LZC 压缩↔解压回环自测
    └── test_unpack_end2end.py  # 合成源码包的端到端解包测试
```

---

## 1. 这是什么包

SAP 里从 SE38 / SE80 导出的程序源码包（"Download Program"），长这样：

```
<任意名字>.zip
├── K984699.<ext>    对象头（Kopf）：程序名、属性、时间戳、依赖
└── R984699.<ext>    对象体（Rumpf）：文本头 + 若干 LZH 压缩块
```

`K` / `R` 是德文 Kopf（头）/ Rumpf（体）。**不要**用文本编辑器直接打开这类文件 —— 内容是 SAP 内部 LZH 压缩的二进制。

> **成员后缀随系统命名变化，不具代表性**（实测有 `.ED1`、`.TD1`，也可能无后缀）。
> 工具按 `K<数字>.*` / `R<数字>.*` 的命名形态识别成员，不以扩展名为依据。

## 2. 用法

依赖：Python ≥ 3.8（仅标准库，无第三方依赖）。示例命令统一写 `python`：
Linux/macOS 上若只有 `python3` 命令请自行替换，Windows 上也可用 `py`。

```bash
# 解包并落盘（默认输出到 ./sap_src_<包名>/）
python sap_src_unpack.py <包.zip>

# 只看清单，不落盘
python sap_src_unpack.py <包.zip> --list

# 去掉 SAP 自动生成的横幅（XSD$ 头、*** 分隔线、"THIS FILE IS GENERATED"）
python sap_src_unpack.py <包.zip> --no-banner

# 合并源码打到标准输出（管道给 grep / more）
python sap_src_unpack.py <包.zip> --stdout | more

# 指定输出目录
python sap_src_unpack.py <包.zip> -o out
```

也支持直接喂单个 R 体文件（任意后缀，非 zip 输入一律按 R 体处理）：

```bash
python sap_src_unpack.py R984699.ED1
python sap_src_unpack.py R984699.dat
```

### 输出

```
sap_src_<包名>/
├── ZDEMO_IF_SBSJ.abap       每个对象一个文件
├── ZDEMO_IF_SBSJ_2.abap      同名对象自动加 _2 后缀（接口声明 vs 实现）
├── LCL_DEMO.abap             类
├── ALL_SOURCES.abap          合并版，方便整体浏览 / grep
└── metadata.txt              时间戳、系统、导出人、对象清单、SAPCOMPONENT 依赖
```

---

## 3. 包格式（逆向自实际样本）

### 3.1 压缩层

`R` 体 = 文本头 + 连续压缩块：

```
[ASCII 文本头, 遇非可打印字节结束]
[块1][块2][块3]...
```

每块 = **8 字节 SAP 头** + **LZH 压缩数据**：

```
偏移:  0   1   2   3   4   5   6   7
      len(len32 LE)  alg  1f  9d  extra
                    ^^^^^^^ magic
```

- 算法 = **LZH**（Lempel-Ziv + Huffman，MaxDB 数据库同款）
- `len` = 解压后长度
- 每块解出 **16384** 字节（末块可能不足）
- 块边界必须靠解压器的 `reader.bytes_read` 精确推进 —— **不能**靠扫 magic，
  压缩流里会偶然出现 `1f 9d`

LZH 实现在 `sap_lzh.py`（[pysapcompress](https://github.com/CoreSecurity/pysap)
的 Python 移植，源自 MaxDB 压缩代码，
由 TypeScript sapcomp 移植而来）。

### 3.2 记录层

解压后是一串记录，每条 **4 字节头 + payload**：

```
00 00 <len: u16be> <payload: len-4 字节>
```

`len` 是**整条记录长度**（含 4 字节头）。

payload 有三种形态，靠前 2 字节区分：

| 标记 | 含义 | 内容 |
|---|---|---|
| `0x2020` | 源码行 | UTF-16LE，固定 255 字符宽，补空格 |
| `0x2046` | 对象头 | UTF-16LE，`XSD$ IS <用户> <日期> <程序> ...` |
| 其它 | 属性表 | ASCII，`HATAB` / `HABAPREADREPOS` / `SMODILOG` 等 |

**`0x2046`（XSD$）记录标志着一个代码块开始** —— 这是切分源码区段的依据。

### 3.3 对象清单行

导出包会在源码之间交错写入对象清单行（不是代码）：

```
FUGRZDEMOGIF15_SW                           FUNCZDEMO_IF_SBRQ
CIFUGRZDEMOGIF15_SW                         FUNCZDEMO_IF_SBRQ     ← CI/CU/CV/FL/PR/SV 前缀
ZDEMO_IF_SBSJ                 AES_PAGE                       EZDEMOSPAGE
ED1K984699          000002LIMUFUNCZDEMO_IF_SBSJ
```

这些行必须在解包时剔除，否则会混进 `.abap` 文件。

### 3.4 元数据行（<格式令牌>K）

`<格式令牌>K<id>` 开头的行是属性清单。**格式令牌随系统命名变化**（实测有
`ED1K` / `TD1K`），解析按形态匹配、不写死令牌。示例：

```
ED1K984699          KOEQ1       SYSTDEVUSER       20261026162654
ED1K984699          000002LIMUFUNCZDEMO_IF_SBRQ
ED1K984699          000002SAPCOMPONENT                  BSNAGT,200,0008
ED1K984699          000003R3TRFUGRZDEMOGIF15_SW
```

`K` 体里还有程序级元数据（时间戳行的令牌同样随系统变化，如 `ED1` / `TD1`）：

```
DEVUSER        K EQ1        1   0   3 ...
ED1 f 0000 20261026162654 S4DDEV       devadm        ← 创建/修改时间戳
```

---

## 4. 两个坑（已解决，改脚本时别踩回去）

### 坑 1：把 ASCII 表格数据误当 UTF-16

有些 `0x2020` 开头的记录其实是 ASCII 属性表数据。硬解 UTF-16 会得到一堆 CJK 乱码。

**解法**：真 UTF-16LE 的**奇数位字节必为 0**（ASCII 字符高位），
用「奇数位零字节比例 ≥ 0.9」判定。实测该样本 1111 真 / 259 假，分得很干净。

```python
def _odd_zero_ratio(payload):
    body = payload[2:]
    odd = body[1::2]
    return sum(1 for b in odd if b == 0) / len(odd)
```

### 坑 2：元数据行误杀真代码

第一版用「整行没有 ABAP 关键字 ⇒ 是元数据」，结果**误杀了 `OTHERS = 3.`**
（`OTHERS` 是 ABAP 关键字但不在关键字表里）。

**解法**：改成**白名单式** —— 只在满足以下两条时判为元数据：

1. 首个 token 命中「已知对象名」集合（该集合从清单行里预先收集）
2. 且形态为「大写名 + ≥5 空格 + 字段」

宁可漏判也不误杀。判据确定后代码零丢失。

---

## 5. 代码结构

| 函数 | 职责 |
|---|---|
| `decompress_r_body()` | 遍历 LZH 块解压，用 `bytes_read` 精确推进块边界 |
| `_odd_zero_ratio()` | UTF-16 / ASCII 判别（见坑 1） |
| `_decode_payload()` | payload → `(kind, text)`，kind ∈ ascii / source / header |
| `parse_records()` | 记录流切分 |
| `collect_known_object_names()` | 收集已知对象名（供元数据行判定） |
| `is_pack_meta_line()` | 元数据行判定（见坑 2，白名单式） |
| `collect_source_lines()` | 还原 ABAP 文本行（按 XSD$ 头切代码块） |
| `split_objects()` | 按 FUNCTION / REPORT / INCLUDE / CLASS 切对象 |
| `parse_metadata()` | 抽时间戳、系统、对象清单、SAPCOMPONENT |
| `strip_banner()` | 去 SAP 自动横幅（`--no-banner`） |

---

## 6. 验证方法

解包结果与「手工解出的参照版本」做了双向 diff：

- 关键逻辑抽查 10 项全在位（`FORM frm_get_pernr`、`CALL FUNCTION 'ZDEMO_FM_GET_0041'`、
  `IF im_period >= 2024.`、`DELETE ADJACENT DUPLICATES` 等）
- 中文注释完整（参照版反而因按 `0x00` 切分而截断）
- 被注释掉的历史代码块完整保留
- `OTHERS = 3.` 未被误杀
- 对象切分正确：接口声明 / 实现 / include / 类 各自成文件

**改脚本后请重跑这个 diff**，确认代码零丢失：

```bash
python sap_src_unpack.py <包.zip> -o chk --no-banner
grep -c "SELECT\|LOOP AT\|FORM \|ENDFORM\|METHOD" chk/ALL_SOURCES.abap
```

另外 `tests/` 下是自测（不依赖样本包）：

```bash
python tests/test_sap_lzh.py        # 压缩层回环
python tests/test_unpack_end2end.py   # 合成包端到端 (含任意后缀/令牌泛化场景)
```

---

## 7. 已知限制

1. **只支持 K/R 体压缩包**。若导出的是 `.abap` / `.txt`（SE38 里 "Download as text"），
   直接读即可，不用这个工具。
2. `object1.abap` 可能是空壳 —— 导出包生成的残片，剥离横幅后无实际内容。
3. 元数据里的 `LIMUFUNC` / `LIMUREPS` 等类型名带尾部空格，输出时未 trim（不影响使用）。
4. 未覆盖：class pool（类池里多个类的合并导出）之外的更多 SAP 对象类型
   （如 `CLAS` 独立类、`INTF` 接口、`.prog.xml` 等）—— 遇到新类型需要补
   `split_objects()` 的识别规则。
5. **扩展名/格式令牌随系统变化**：成员后缀与清单/时间戳行的格式令牌（实测有
   ED1/TD1 系）都随系统命名变化，不具代表性。工具一律按命名形态和内容结构
   识别，不以后缀/令牌为准；遇到新令牌的包无需改代码。已用 40 个真实包验证
   `--no-banner` 剔除约 3.2 万行伪影、真代码零丢失。

---

## 8. 配套 ABAP 程序：ZUD（传输请求下载/上传）

`abap/ZUD.abap` 来自开源项目
[furkancosgun/Transport-Management-Tool](https://github.com/furkancosgun/Transport-Management-Tool)
（MIT，作者 Furkan COSGUN，许可全文见 [abap/LICENSE-ZUD](abap/LICENSE-ZUD)）。
本仓库携带的副本只做了 Pretty Printer 格式化，并加了一处小改动：
`AT SELECTION-SCREEN OUTPUT` 里目标文件夹为空时默认填桌面。

安装：SE38 新建程序 `ZUD`，粘贴整份代码并激活即可。

- **下载**：把已释放（Released）的传输请求的 cofile/data 两个文件打包成 ZIP
  保存到本地
- **上传**：把 ZIP 里的 cofile/data 写回服务器的 `DIR_TRANS/cofiles`、`data`
  目录，并可选三种后续动作——立即触发 STMS 导入 / 只填充 E07* 传输表
  （等价于 `tp cmd <TR> <SID>` 对象清单导入）/ 什么都不做

典型用法：在开发机用 ZUD 把 TR 拉成 ZIP 传给目标系统，再在目标系统上传导入；
配合本工具可以继续解包 SE38 导出的源码包。

---

## 9. 相关背景

- **这套包格式是什么**：SAP GUI 经典 ABAP 编辑器导出源码用的 K/R 体容器
  （Kopf/Rumpf + LZH 压缩）。成员后缀与包内格式令牌（ED1、TD1 等记号）随
  系统命名变化、不具代表性，因此本文档按结构描述而不以令牌命名。SAP 官方
  `abap-file-formats` 仓库（给 abapGit 用的）**不覆盖**这个格式，
  本工具的格式说明是逆向得到的。
- **REPOSRC 压缩**：SAP 表 `REPOSRC` 里的源码用同一套 LZH 算法存储。
  背景资料见 <https://www.daniel-berlin.de/devel/sap-dev/decompress-abap-source-code>
- **LZH 移植**：`sap_lzh.py` 源自 pysapcompress
  (<https://github.com/CoreSecurity/pysap>)，后者移植自 TypeScript sapcomp
  (<https://git.sr.ht/~xje4/sapcomp>)，最终源自 SAP MaxDB 压缩代码。

---

## 10. 许可证

本仓库整体按 **GPL-2.0** 发布，全文见 [LICENSE](LICENSE)。
`sap_lzh.py` 移植自 GPL-2.0 许可的
[pysapcompress](https://github.com/CoreSecurity/pysap)，决定了仓库整体协议。

例外：`abap/ZUD.abap` 是 MIT 许可的第三方代码（原作者 Furkan COSGUN，
见 [abap/LICENSE-ZUD](abap/LICENSE-ZUD)）。MIT 与 GPL-2.0 兼容，随仓库
分发时保留其原始版权声明即可。
