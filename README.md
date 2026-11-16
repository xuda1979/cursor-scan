# Cursor-Scan

本地安全债扫描器：对「vibe-code」（AI 生成）项目做安全体检，输出逐项
证据（file:line + 修复建议）、健康度评分卡（0–100 + A–F 等级），并可按
严重度做 CI 门禁（exit code）。

纯本地运行，无网络、无 GPU。规则引擎基于 tree-sitter AST（Python/JS/TS）
与正则回退，覆盖扫描目录下所有文本文件。

## 功能

- **规则维度**（7 个）：
  - 弱密码学（crypto）：md5/sha1 弱哈希、DES、ECB 模式、固定 IV、硬编码随机种子
  - 硬编码秘密（secrets）：AWS key、Slack/GitHub/Google/Stripe token、私钥块、通用 `key = 值` 可疑赋值
  - 不安全反序列化（deserialization）：pickle、不安全 `yaml.load`、`eval`/`exec` 外部输入
  - 注入（injection）：SQL 字符串拼接、shell 拼接（`subprocess` / `os.system`）、`shell=True`
  - 文件权限（permissions）：`chmod 0777`、写入 /tmp 无校验
  - 访问控制（access_control）：缺鉴权路由等
  - 依赖风险（dependencies）：`requirements*.txt` / `package.json` 中的已知漏洞版本（离线 CVE 表）与未固定版本
- **评分卡**：每维度从 100 起，按严重度扣分（low 5 / medium 12 / high 20 / critical 30），
  总分 = 各维度均分；等级 A≥90, B≥75, C≥60, D≥40, F<40。每项发现都给出
  `file:line`、严重度、解释与修复建议，保证可解释。
- **输出格式**：text（默认）/ JSON / SARIF 2.1.0。
- **CI 门禁**：`--fail-on` 指定严重度阈值，命中即 exit 1。

## 安装

需要 Python 3.10+。推荐使用 venv：

```bash
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e .
```

依赖：`tree-sitter`、`tree-sitter-python`、`tree-sitter-typescript`、`pytest`（开发）。

## 使用

```bash
cursor-scan <项目目录>          # 文本报告
cursor-scan . --format json    # JSON
cursor-scan . --format sarif   # SARIF 2.1.0
cursor-scan . --fail-on medium # 有任何 medium+ 发现即 exit 1
```

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `path` | 要扫描的项目目录 | `.` |
| `--format` | `text` / `json` / `sarif` | `text` |
| `--fail-on` | 门禁严重度 `low`/`medium`/`high`/`critical` | `high` |
| `--max-bytes` | 超过该字节数（文件）跳过，计入 skipped | 2 MiB |
| `--history-dir` | 扫描快照保存目录 | `./history` |
| `--no-save` | 不写入历史快照 | |
| `--history` | 列出已保存的扫描快照（最新在前） | |
| `--diff` | 比较两张快照，如 `--diff <before> <after>`（目标 slug 或文件路径） | |
| `--version` | 打印版本 | |

退出码：`0` 完成且无达到门禁的发现；`1` 有达到门禁的发现；`2` 用法/环境错误（如目录不存在、无权限）。

## 扫描历史

每次扫描默认保存一张 JSON 快照到 `history/`（可 `--no-save` 关闭）：

```bash
cursor-scan .                    # 扫描并保存快照
cursor-scan --history            # 查看历史
cursor-scan --diff proj-20261115-101000.json proj-20261115-102000.json  # 两次扫描差异
```

`--diff` 按 `(rule_id, file, line)` 对齐两次扫描，列出新增 / 修复 / 仍在的问题，并给出
评分与等级的变化。快照是纯 JSON（`result_to_dict` 结构），可被离线仪表板直接读取。

## 评分模型

- 每个维度一个分数，从 100 分开始，每命中一条按严重度扣分：critical −30、high −20、medium −12、low −5，下限 0。
- 总分 = 各维度分数的整数平均。无发现时为 100 / A。
- 评级：A（≥90）、B（≥75）、C（≥60）、D（≥40）、F（<40）。

## 开发

```bash
source .venv/bin/activate
python -m pytest tests/ -q   # 全量测试
```

`fixtures/` 下有两棵树用于验收测试：

- `fixtures/scan_bad/`：故意植入漏洞的七个文件（弱密码学 / 秘密 / 反序列化 / 注入 / 权限 / 依赖清单），
  共 23 条期望规则 ID，检测率须 ≥ 90%。
- `fixtures/scan_good/`：干净项目，须零误报（0 findings、100 / A）。

验收标准（SPEC AC1–AC7）：

| AC | 状态 |
| --- | --- |
| 1. scan_bad 检测率 ≥ 90% | ✅ 21/21 → 23/23（100%） |
| 2. scan_good 零误报 | ✅ 0 findings / 100 / A |
| 3. 评分卡 + 逐项证据 | ✅ |
| 4. 历史快照 + diff | ✅ |
| 5. CLI 门禁 + SARIF | ✅ |
| 6. Web dashboard | ⏳ P2 |
| 7. 测试 + README | ✅ |

## 路线图

- [x] P0 规则引擎 + 评分卡
- [x] P1 CLI + SARIF + 门禁
- [x] P2a 扫描历史快照 + diff（CLI）
- [ ] P2b Web dashboard（读取历史快照）
- [x] P3 依赖风险 flag（requirements.txt / package.json 高危已知库）
