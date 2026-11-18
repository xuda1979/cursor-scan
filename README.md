# Cursor-Scan

本地安全债扫描器：对「vibe-code」（AI 生成）项目做安全体检，输出逐项
证据（file:line + 修复建议）、健康度评分卡（0–100 + A–F 等级），并可按
严重度做 CI 门禁（exit code）。

纯本地运行，无网络、无 GPU。规则引擎基于 tree-sitter AST（Python/JS/TS）
与正则回退，覆盖扫描目录下所有文本文件。

## 功能

- **规则维度**（8 个）：
  - 弱密码学（crypto）：md5/sha1 弱哈希、DES、ECB 模式、固定 IV、硬编码随机种子
  - 硬编码秘密（secrets）：AWS key、Slack/GitHub/Google/Stripe token、私钥块、通用 `key = 值` 可疑赋值
  - 不安全反序列化（deserialization）：pickle、不安全 `yaml.load`、`eval`/`exec` 外部输入
  - 注入（injection）：SQL 字符串拼接、shell 拼接（`subprocess` / `os.system`）、`shell=True`
  - 文件权限（permissions）：`chmod 0777`、写入 /tmp 无校验
  - 访问控制（access_control）：缺鉴权路由等
  - 依赖风险（dependencies）：`requirements*.txt` / `package.json` 中的已知漏洞版本（离线 CVE 表）与未固定版本
  - 跨站脚本（xss）：`innerHTML` / `insertAdjacentHTML` / `outerHTML` DOM 写入、React `dangerouslySetInnerHTML`、`document.write`、Jinja `render_template_string` / `Markup` / `|safe` 关闭转义
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
cursor-scan --serve            # 启动离线 Web 仪表板 (http://127.0.0.1:8080/)
```

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `path` | 要扫描的项目目录 | `.` |
| `--format` | `text` / `json` / `sarif` | `text` |
| `--fail-on` | 门禁严重度 `low`/`medium`/`high`/`critical` | `high` |
| `--max-bytes` | 超过该字节数（文件）跳过，计入 skipped | 2 MiB |
| `--ignore` | 抑制匹配的发现（可重复）。单个 glob 匹配规则 ID / 文件名 / 相对路径；`RULE[:FILE[:LINE]]` 分字段匹配 | |
| `--history-dir` | 扫描快照保存目录 | `./history` |
| `--no-save` | 不写入历史快照 | |
| `--history` | 列出已保存的扫描快照（最新在前） | |
| `--diff` | 比较两张快照，如 `--diff <before> <after>`（目标 slug 或文件路径） | |
| `--serve` | 启动离线 Web 仪表板，浏览历史 / 快照 / 差异 | |
| `--host` / `--port` | 仪表板监听地址 / 端口 | `127.0.0.1` / `8080` |
| `--version` | 打印版本 | |

退出码：`0` 完成且无达到门禁的发现；`1` 有达到门禁的发现；`2` 用法/环境错误（如目录不存在、无权限）。

## 忽略误报

`--ignore`（可重复）或项目根目录 `.cursor-scan.json` 里的 `"ignore"` 列表可抑制
特定发现的报告与评分（被抑制者计入职级门禁判定之外的 `suppressed` 列表，仍在
text 报告与 JSON 输出的 `suppressed` 字段中可见）：

```bash
cursor-scan . --ignore 'deps.*' --ignore 'injection.sql_concat:app.py'
```

```json
{ "ignore": ["secrets.hardcoded_key", "perms.*:tmpclean.sh"] }
```

两种模式：

- 单个 glob（`fnmatch` 语义，区分大小写）——匹配**任意一个**：规则 ID、文件名、相对路径。
  如 `crypto.*` 抑制全部弱密码学规则；`tests/*.py` 抑制 `tests/` 下所有发现。
- `RULE[:FILE[:LINE]]`——已给出的字段必须**全部**匹配。例如 `injection.sql_concat:app.py`
  只抑制 `app.py` 中的 SQL 拼接，`injection.sql_concat:app.py:11` 进一步限到第 11 行。

CLI 与配置文件可以并存；门禁（`--fail-on`）只评估未被抑制的发现。

## 扫描历史

每次扫描默认保存一张 JSON 快照到 `history/`（可 `--no-save` 关闭）：

```bash
cursor-scan .                    # 扫描并保存快照
cursor-scan --history            # 查看历史
cursor-scan --diff proj-20261115-101000.json proj-20261115-102000.json  # 两次扫描差异
```

`--diff` 按 `(rule_id, file, line)` 对齐两次扫描，列出新增 / 修复 / 忽略 / 仍在的问题，并给出
评分与等级的变化。若后一次扫描通过 `--ignore` / `.cursor-scan.json` 抑制了某条发现，它会被归入
「忽略」（而不是「修复」），避免把"只是改用了忽略"误报成"已经修好"。快照是纯 JSON
（`result_to_dict` 结构），可被离线仪表板直接读取。

## Web 仪表板（离线）

`cursor-scan --serve` 启动一个零依赖的本地 Web 仪表板（纯 Python `http.server`，
无网络、无 GPU），浏览全部扫描历史：

```bash
cursor-scan .                    # 生成/刷新快照
cursor-scan --serve              # http://127.0.0.1:8080/
cursor-scan --serve --port 9000  # 自定义端口
```

页面：历史列表（最新在前，含评分/等级）、单个快照详情（评分卡 + 逐项证据 +
代码片段）、双快照对比（`/diff?before=<ref>&after=<ref>`，新增 / 修复 / 忽略 / 仍在）。
另有 JSON API：`/api/history.json`、`/api/snapshot/<ref>`。仪表板只读历史目录，
快照引用经路径校验（拒绝目录穿越），所有扫描内容 HTML 转义（防存储型 XSS）。

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

- `fixtures/scan_bad/`：故意植入漏洞的 43 个文件（弱密码学 / 秘密 / 反序列化 / 注入 / 权限 / 访问控制
  / 依赖清单 / 跨站脚本），共 91 条期望规则 ID，检测率须 ≥ 90%。注入规则覆盖 Python / JS / PHP / Java /
  Ruby / Go / C# / Kotlin / Rust / Perl / Lua / C/C++ / Swift / Shell / R / PowerShell / SQL / VB.NET / Scala / Groovy / Dart / Objective-C / Elixir / Erlang。
- `fixtures/scan_good/`：干净项目，须零误报（0 findings、100 / A）。

验收标准（SPEC AC1–AC7）：

| AC | 状态 |
| --- | --- |
| 1. scan_bad 检测率 ≥ 90% | ✅ 91/91（100%） |
| 2. scan_good 零误报 | ✅ 0 findings / 100 / A |
| 3. 评分卡 + 逐项证据 | ✅ |
| 4. 历史快照 + diff | ✅ |
| 5. CLI 门禁 + SARIF | ✅ |
| 6. Web dashboard | ✅ 离线（stdlib，无依赖） |
| 7. 测试 + README | ✅ |

## 路线图

- [x] P0 规则引擎 + 评分卡
- [x] P1 CLI + SARIF + 门禁
- [x] P2a 扫描历史快照 + diff（CLI）
- [x] P2b Web dashboard（读取历史快照）
- [x] P3 依赖风险 flag（requirements.txt / package.json 高危已知库）
- [x] P4 XSS 检测维度（DOM sinks / React / document.write / 模板渲染）
