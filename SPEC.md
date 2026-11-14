# 16 — Cursor-Scan: vibe-code 安全债扫描桌面版

## 定位
Cursor（> $1B ARR）生态切片：桌面工具，扫描 vibe-code 项目根目录，识别「安全债」
（未加缓冲区校验、弱哈希、secret 硬编码、依赖版本、无测试的高风险改动？）——
给独立/小型 dev 一个开机就能跑的安全体检。母市场 Cursor $1B+（新贵已过线）。

## 主要痛点
- AI 生成的代码带着「安全债」（用 md5、明文存储、无鉴权、弱随机）
- 开发者不知道哪部分是 AI 生成、哪些模式危险
- 想要「是/否」的安全健康度评分 + 修复指导（开机体检式）

## 功能需求
1. 项目扫描器（本地遍历 AST）：
   - 弱密码学：md5/sha1/sha256 弱用途、DES、ECB、固定 IV、硬编码随机种子
   - 秘密硬编码：令牌、cloud creds、私钥
   - 不安全反序列化：pickle/不安全 yaml.load、eval/exec 于外部输入
   - 注入：SQL 字符串拼接、shell 拼接（subprocess）
   - 文件权限：chmod 0777、写入 /tmp 无校验
   - 缺鉴权路由（与 03 规则共享思路）
2. 健康度评分卡（0–100 + 等级）：
   - 分维度：密码学/注入/秘密/访问控制/依赖
   - 每项：证据 file:line、严重度、修复建议（代码 snippet 示例）
3. 桌面版：
   - 简单 GUI（Tauri/Electron 或 Web 仪表板，选 Web dashboard 更轻）
   - 拖入项目目录 → 扫描 → 报告（保存历史比较）
4. 依赖风险（v1 可选）：读取 requirements.txt/package.json，对高危已知库给 flag
5. CLI 模式 + SARIF 输出（与 03 输出复用）

## 非目标
- 运行时防护
- 完整语义分析（本项目 = 规则 + 模式）

## 技术栈
- Node v22（前端 + 扫描服务）或 Python 3.14（规则引擎）
- tree-sitter（Python/JS 等语言 AST）
- 桌面壳：Electron（重）或 web 仅（更轻）——v1 用 `npx serve` 本地 dashboard
- 测试：fixture「坏/好」项目

## 低算力守则
见全局（本地扫描/规则 + 输出，无 GPU）。

## AC
1. 对 fixture malj（含弱密码学/注入/秘密）正确检出率 ≥ 90%
2. 对 good fixture 零误报
3. 评分卡生成且可解释（逐项证据）
4. 每次扫描结果保存历史 → 两次扫描差异视图
5. CLI 模式（exit code 门禁）+ SARIF
6. Web dashboard 可用（可离线）
7. 测试 + README

## Phases
- P0: 规则引擎（密码学/注入/秘密）+ 评分
- P1: CLI + SARIF + 门禁
- P2: Web dashboard + 历史
- P3: 依赖风险 flag

## 里程碑
M1: 规则扫描 + 评分（MVP）
M2: 历史 + dashboard
M3: 依赖 + 集成

## 变现
- 开源 CLI，桌面 Pro = 多项目/报告
