# VulnScanner AI

一个集成了大语言模型 (LLM) 的自动化漏洞扫描工具。

## 架构

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Frontend  │────▶│  FastAPI    │────▶│   Celery    │
│  (React)    │     │  Backend    │     │   Worker    │
└─────────────┘     └─────────────┘     └─────────────┘
                           │                   │
                    ┌──────┴──────┐            │
                    ▼             ▼            ▼
              ┌──────────┐ ┌──────────┐ ┌─────────────┐
              │PostgreSQL│ │ MongoDB  │ │  Scanners   │
              │  (结构)   │ │  (原始)   │ │ Nmap/Nuclei │
              └──────────┘ └──────────┘ └─────────────┘
                                              │
                                              ▼
                                        ┌──────────┐
                                        │   LLM    │
                                        │ Analysis │
                                        └──────────┘
```

## 快速开始

### 使用 Docker Compose (推荐)

```bash
cd docker
docker-compose up -d
```

- Frontend: http://localhost:3000
- Backend API: http://localhost:8000
- API Docs: http://localhost:8000/docs

### 本地开发

1. **启动依赖服务**
```bash
# PostgreSQL, MongoDB, Redis
docker-compose up -d postgres mongodb redis
```

2. **后端**
```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# 启动 API
uvicorn app.main:app --reload

# 启动 Celery worker (新终端)
celery -A tasks.celery_app worker --loglevel=info
```

3. **前端**
```bash
cd frontend
npm install
npm run dev
```

## API 示例

```bash
# 创建扫描任务
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "scan_type": "quick"}'

# 获取扫描结果
curl http://localhost:8000/api/v1/scans/{scan_id}

# 获取漏洞列表
curl http://localhost:8000/api/v1/scans/{scan_id}/vulnerabilities
```

## 扫描器

- **Nmap**: 端口扫描、服务识别、漏洞脚本
- **Nuclei**: 基于模板的漏洞检测

## ⚠️ 安全警告

1. **仅扫描授权目标** - 未经授权的扫描可能违法
2. **控制扫描频率** - 避免 DoS 目标服务器
3. **数据脱敏** - 不要将敏感数据发送给公有云 LLM
