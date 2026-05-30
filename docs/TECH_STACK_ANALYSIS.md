# Shelling AI 技术栈对比分析

## 技术栈一览

| 层面 | Shelling AI 选型 | 
|------|-----------------|
| **后端框架** | FastAPI (Python 异步) |
| **数据库** | PostgreSQL + MongoDB + Redis (三库架构) |
| **任务队列** | Celery + Redis |
| **前端** | React 18 + TypeScript + Vite + Tailwind + React Query |
| **扫描引擎** | Kali 容器 (40+ 工具) + HTTP 微服务封装 |
| **AI/LLM** | LangChain + OpenAI 兼容 API |
| **部署** | Docker Compose (7 服务) |

---

## 对标同类平台

| 平台 | 定位 | 技术栈特点 |
|------|------|-----------|
| **Nessus** | 商业漏洞扫描器 | C/C++ 闭源，自有引擎 |
| **OpenVAS (Greenbone)** | 开源漏洞扫描器 | C/Python，PostgreSQL，自有 NASL 脚本引擎 |
| **Nuclei + PDCP** | 模板驱动扫描 | Go 单二进制，YAML 模板，Cloud 平台用 React |
| **OWASP ZAP** | Web 应用安全测试 | Java，插件架构，桌面 GUI + API |
| **DefectDojo** | 漏洞管理平台 | Django + Celery + PostgreSQL + React |
| **Qualys** | 商业云安全平台 | 微服务架构，Java/Go 后端 |
| **Faraday** | 协作型安全平台 | Python (Flask) + PostgreSQL + Vue |

---

## 各技术选型优缺点

### 1. FastAPI (vs Django/Flask/Go/Java)

**✅ 优势**

- **原生异步** — 高并发扫描状态查询、日志推送场景下，async I/O 性能优于 Django 同步模型
- **自动生成 OpenAPI 文档** — `/docs` 即用，前后端联调成本低
- **类型驱动** — Pydantic schema 与请求/响应强绑定，减少运行时错误
- **轻量灵活** — 不像 Django 那样"全家桶"，适合微服务风格

**❌ 劣势**

- **生态较小** — Django 有庞大的插件生态（admin、auth、ORM），FastAPI 需要自己拼装
- **ORM 非原生** — SQLAlchemy 2.0 学习曲线陡峭，不像 Django ORM 那样"开箱即用"
- **社区规模** — 相比 Java/Go 在企业级安全工具中的成熟度，FastAPI 仍属年轻
- **缺乏管理后台** — 没有 Django Admin 那样的内置后台，AdminPanel 需要完全自建

**对标：** DefectDojo 用 Django（成熟但慢），Faraday 用 Flask（轻但缺异步）。FastAPI 在性能和开发体验间取得了不错的平衡，但为"快速迭代安全平台"付出了生态代价。

---

### 2. 三库架构：PostgreSQL + MongoDB + Redis

**✅ 优势**

- **职责分离清晰** — 结构化实体（用户/任务/配置）→ PG，原始扫描数据/日志 → MongoDB，缓存/消息 → Redis
- **MongoDB 灵活 schema** — 不同扫描器输出格式差异大，文档模型比关系模型更自然
- **Redis 实时性** — 扫描日志实时推送、Celery broker 一石二鸟

**❌ 劣势**

- **运维复杂度 ×3** — 三套数据库意味着备份、监控、升级、故障排查成本翻倍
- **数据一致性** — 跨库事务需要应用层保证，无外键约束
- **小团队负担** — 对比 Nuclei 的"零数据库"（纯文件输出）或单库架构，三库对小团队偏重
- **MongoDB 使用深度有限** — 目前主要用于日志存储，没有充分利用文档查询/聚合能力，可能是"过度设计"

**对标：** OpenVAS 仅用 PostgreSQL（单库简洁），Nuclei + PDCP 用 PostgreSQL + Redis（两库）。三库架构适合中大型部署，但对 MVP 阶段来说复杂度偏高。

---

### 3. Celery 任务队列

**✅ 优势**

- **成熟稳定** — Python 生态中最广泛使用的任务队列
- **并发控制** — `MAX_CONCURRENT_SCANS=5` 精确控制扫描资源
- **结果持久化** — 扫描任务可追踪状态（PENDING→RUNNING→COMPLETED/FAILED）

**❌ 劣势**

- **同步桥接麻烦** — Celery worker 是同步的，需要 `run_async()` + `asyncio.new_event_loop()` 桥接 FastAPI 的异步代码，容易出现事件循环泄漏
- **资源占用** — Celery worker 进程内存开销大，空闲时也占用资源
- **调试困难** — 分布式任务的调试和追踪不如简单的后台线程直观
- **替代方案多** — 对于扫描场景，Go 的 goroutine 或 Python 的 `asyncio.TaskGroup` 可能更轻量

**对标：** DefectDojo 也用 Celery（同痛点），Nuclei 直接在进程内并发（Go 原生 goroutine，无额外组件）。Celery 是 Python 生态的安全选择，但异步桥接是最大的技术债。

---

### 4. React 18 + TypeScript + Vite + Tailwind

**✅ 优势**

- **类型安全** — TypeScript + API 接口定义，前后端契约清晰
- **开发体验** — Vite HMR 极快，React Query 减少大量样板代码
- **Tailwind** — 原子化 CSS，dark mode 开箱即用，组件样式高内聚
- **React Query** — 服务端状态管理（轮询、缓存、乐观更新）非常适合扫描任务的实时状态

**❌ 劣势**

- **Bundle 体积** — React + React Query + Recharts + Lucide 打包后体积较大，安全工具通常偏好轻量
- **前端复杂度** — 对比 OpenVAS 的纯服务端渲染或 ZAP 的桌面 GUI，SPA 增加了 XSS 攻击面（讽刺的是安全工具自身）
- **Recharts 局限** — 图表库功能偏基础，大数据量可视化不如 ECharts/D3
- **无 SSR/SSG** — 纯 CSR 对 SEO 和首屏加载不友好（但安全工具通常内网使用，影响不大）

**对标：** PDCP 用 React（同栈），DefectDojo 用 React（同栈），Faraday 用 Vue。React 是安全平台前端的事实标准选择。

---

### 5. Kali 容器 + HTTP 微服务封装

**✅ 优势**

- **工具丰富** — 40+ 预装安全工具，覆盖网络/漏洞/Web/凭证/后渗透全链路
- **隔离安全** — 工具在独立特权容器中执行，不影响主后端
- **统一接口** — `KaliClient` 通过 HTTP API 统一调度，后端无需关心工具安装/路径
- **可扩展** — 新工具只需在 Kali 容器中安装 + 注册 ScannerType 枚举

**❌ 劣势**

- **特权容器风险** — `privileged: true` + `NET_ADMIN` + `NET_RAW` 在生产环境是安全隐患
- **冷启动慢** — Kali 镜像体积大（数 GB），首次拉取和启动耗时
- **单点瓶颈** — 所有扫描器共用一个 Kali 容器，并发扫描时 I/O 和 CPU 互相竞争
- **HTTP 开销** — 每次工具调用都经过 HTTP 序列化/反序列化，对比本地进程调用有额外延迟
- **维护成本** — Kali 滚动更新可能破坏工具兼容性，需要锁定版本

**对标：** Nuclei 是 Go 单二进制分发（极简），OpenVAS 自有 NASL 引擎（封闭但稳定），ZAP Java 插件架构（灵活）。Shelling 的"Kali 全家桶"模式牺牲了轻量性换取了工具广度。

---

### 6. LangChain + OpenAI API

**✅ 优势**

- **快速集成** — LangChain 提供了成熟的 LLM 编排框架
- **模型灵活** — OpenAI 兼容 API 意味着可切换到任何兼容服务（Azure、本地 Ollama 等）
- **Persona 系统** — 可定制 AI 分析角色，适应不同安全场景

**❌ 劣势**

- **LangChain 臃肿** — 抽象层过多，调试链路长，版本升级频繁且破坏性变更多
- **成本不可控** — 每次扫描的 LLM 调用成本随漏洞数量线性增长
- **幻觉风险** — LLM 对漏洞的分析可能产生误导性建议，安全领域容错率极低
- **延迟** — LLM 分析是扫描流程的瓶颈，复杂扫描可能因 LLM 响应慢而超时

**对标：** 传统扫描器（Nessus/OpenVAS/Nuclei）完全不依赖 LLM，用规则/模板引擎。Shelling 的 LLM 集成是差异化优势，但也是最大的不确定性来源。

---

### 7. Docker Compose 部署

**✅ 优势**

- **一键启动** — `docker compose up --build -d` 即可跑完整栈
- **环境一致** — 消除"在我机器上能跑"问题
- **服务隔离** — 7 个服务各自独立，可单独升级/重启

**❌ 劣势**

- **单机限制** — Docker Compose 不支持原生集群编排，无法水平扩展
- **资源要求高** — 7 个容器（含 Kali）最低需要 8GB+ 内存
- **无编排能力** — 对比 Kubernetes，缺乏自动扩缩容、滚动更新、健康检查自愈
- **数据持久化** — 卷挂载方式在多节点场景下不可靠

**对标：** 商业平台（Nessus/Qualys）提供 SaaS 或单安装包，开源平台通常也提供 Docker Compose 作为开发环境。生产部署应考虑 K8s 编排。

---

## 综合评价

```
                 轻量 ◄─────────────────────► 重量
  
  Nuclei/PDCP    ████░░░░░░░░░░░░░░░░░░░░░░
  OWASP ZAP      ████████░░░░░░░░░░░░░░░░░░
  Faraday        ██████████░░░░░░░░░░░░░░░░
  Shelling AI    ████████████░░░░░░░░░░░░░░  ← 当前位置
  DefectDojo     ██████████████░░░░░░░░░░░░
  OpenVAS        █████████████████░░░░░░░░░
  Nessus/Qualys  ██████████████████████████
```

| 维度 | 评分 | 说明 |
|------|------|------|
| **开发效率** | ⭐⭐⭐⭐ | FastAPI + React Query + Tailwind 开发体验优秀 |
| **功能广度** | ⭐⭐⭐⭐⭐ | 40+ 扫描器 + LLM 分析 + 攻击路径 + 报告 |
| **运维复杂度** | ⭐⭐ | 三库 + Celery + Kali 容器，运维门槛高 |
| **可扩展性** | ⭐⭐⭐ | 水平扩展受限于 Docker Compose 单机 |
| **安全性自体** | ⭐⭐⭐ | 特权容器 + SPA 是攻击面，但有 JWT + RBAC |
| **创新性** | ⭐⭐⭐⭐ | LLM 集成是差异点，传统扫描器无此能力 |
| **成熟度** | ⭐⭐ | 相比 Nessus/OpenVAS 数十年积累，仍属早期 |

---

## 总结

Shelling AI 的技术栈选择体现了"功能优先、快速迭代"的策略。三库 + Kali 全家桶 + LLM 赋予了强大的功能广度，但运维复杂度和成熟度是需要持续优化的方向。最大的差异化优势在于 LLM 驱动的漏洞分析和攻击路径推理，这是传统扫描器所不具备的。

### 优化建议

| 优先级 | 方向 | 建议 |
|--------|------|------|
| 🔴 高 | 简化架构 | 评估是否可将 MongoDB 合并入 PostgreSQL（JSONB 列），减少一个数据库依赖 |
| 🔴 高 | 替换 LangChain | 考虑直接调用 OpenAI SDK，减少抽象层开销和版本依赖 |
| 🟡 中 | 容器编排 | 提供 Kubernetes Helm Chart 作为生产部署选项 |
| 🟡 中 | 扫描器隔离 | 将单 Kali 容器改为按扫描类型动态创建的临时容器，避免资源竞争 |
| 🟢 低 | 前端瘦身 | 评估 Recharts → 轻量图表库，减少 bundle 体积 |
| 🟢 低 | Celery 替代 | 长期考虑迁移到 `arq`（原生异步任务队列）消除同步桥接 |
