# Kali Docker 集成完成 ✅

## 实现概览

成功实现了基于 Kali Linux Docker 容器的智能扫描环境，支持 LLM 自动选择和按需安装安全工具。

## 架构

```
Backend (Celery Worker)
    ↓
KaliClient (HTTP API)
    ↓
Kali Docker Container (运行扫描工具)
    ├── Nmap ✅
    ├── Masscan ✅
    ├── Nuclei (按需安装)
    └── 其他工具...
```

## 已实现功能

### 1. Kali Docker 容器
- ✅ 基于 `kalilinux/kali-rolling`
- ✅ 配置国内镜像源（清华大学）
- ✅ 预装核心工具：nmap, masscan, netcat, dnsutils等
- ✅ FastAPI 微服务端点
- ✅ 健康检查

### 2. Kali API 服务
运行在容器内的 FastAPI 服务 (端口 8888)：

**端点**：
- `GET /health` - 健康检查
- `POST /execute` - 执行命令
- `POST /install` - 安装工具
- `GET /tools` - 列出工具
- `GET /tools/{name}` - 获取工具信息

### 3. Kali 客户端
Backend 中的 `KaliClient` 类，提供：
- 健康检查
- 命令执行
- 工具安装
- 工具查询
- 自动安装确保

### 4. LLM 智能工具选择器
- ✅ 目标分析（URL/IP/域名）
- ✅ LLM 驱动的工具选择
- ✅ 规则降级策略
- ✅ 工具能力库

**支持的工具**：
- nmap, masscan (端口扫描)
- nuclei, nikto (Web漏洞)
- sqlmap (SQL注入)
- sslscan (SSL/TLS)
- whatweb (技术识别)
- subfinder, httpx (信息收集)
- hydra (密码破解)

### 5. 重构的扫描器
- ✅ `KaliBaseScanner` - 通用 Kali 扫描器基类
- ✅ `KaliNmapScanner` - Nmap 集成
- ✅ `KaliNucleiScanner` - Nuclei 集成

### 6. Schema 更新
新增配置选项：
```python
auto_select_tools: bool = True  # LLM 自动选择工具
```

保持向后兼容：
```python
enable_port_scan: bool = True  # 手动模式
enable_nuclei: bool = True     # 手动模式
```

## Docker Compose 配置

```yaml
kali_scanner:
  build: Dockerfile.kali
  ports:
    - "8888:8888"
  privileged: true  # 某些工具需要
  cap_add:
    - NET_ADMIN
    - NET_RAW
  networks:
    - scanner_network
```

## 测试结果

```
✅ 健康检查 - 通过
✅ Nmap 执行 - 通过
✅ 目标分析 - 通过
✅ 规则选择器 - 通过
✅ 工具查询 - 通过
⚠️  Nuclei 安装 - 需要特殊安装脚本（已实现，待测试）
```

## 使用示例

### 1. 启动服务

```bash
cd docker
docker-compose up -d kali_scanner
```

### 2. Python 代码示例

```python
from scanners.kali_client import get_kali_client
from scanners.tool_selector import select_and_prepare_tools

# 获取客户端
client = get_kali_client()

# 智能选择工具
tools, reason = await select_and_prepare_tools(
    target="https://example.com",
    scan_type="quick",
    kali_client=client,
    use_llm=True
)

# 执行扫描
result = await client.execute("nmap", ["-sV", "example.com"])
```

## 文件清单

### 新增文件
- `docker/Dockerfile.kali` - Kali 容器镜像
- `docker/kali-requirements.txt` - Python 依赖
- `docker/kali-service/main.py` - API 服务
- `backend/scanners/kali_client.py` - Kali 客户端
- `backend/scanners/kali_scanner.py` - Kali 扫描器
- `backend/scanners/tool_selector.py` - LLM 工具选择器
- `test_kali.py` - 集成测试

### 修改文件
- `docker/docker-compose.yml` - 添加 kali_scanner 服务
- `backend/app/core/config.py` - 添加 kali_scanner_url
- `backend/app/schemas/scan.py` - 添加 auto_select_tools
- `backend/scanners/__init__.py` - 切换到 Kali 扫描器

## 下一步

1. 在实际扫描任务中集成 LLM 工具选择
2. 完善 Nuclei 等特殊工具的安装脚本
3. 添加更多安全工具支持
4. 优化工具安装性能（批量安装）
5. 前端 UI 支持自动/手动模式切换

## 优势

✅ **智能化**：LLM 根据目标特征自动选择合适的工具  
✅ **按需安装**：工具不存在时自动安装，无需预装全部工具  
✅ **国内加速**：使用清华镜像，安装速度快  
✅ **专业环境**：Kali Linux 生态，工具齐全  
✅ **容器隔离**：扫描环境独立，安全可靠  
✅ **向后兼容**：保留手动配置选项  

## 技术栈

- **容器**：Kali Linux (kalilinux/kali-rolling)
- **API 服务**：FastAPI + Uvicorn
- **客户端**：httpx (异步 HTTP)
- **智能选择**：LLM (GPT-4o) + 规则降级
- **编排**：Docker Compose
