"""Kali Scanner API Service - 运行在 Kali 容器内的微服务"""
import asyncio
import os
import shutil
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from loguru import logger
import uvicorn

# 配置日志
logger.add(
    "/scanner/logs/kali-service.log",
    rotation="10 MB",
    retention="7 days",
    level="INFO"
)

app = FastAPI(title="Kali Scanner Service", version="1.0.0")

# ============= 数据模型 =============

class ExecuteRequest(BaseModel):
    """命令执行请求"""
    command: str = Field(..., description="要执行的命令")
    args: List[str] = Field(default_factory=list, description="命令参数")
    timeout: int = Field(default=300, ge=1, le=3600, description="超时时间（秒）")
    cwd: Optional[str] = Field(default=None, description="工作目录")
    env: Optional[Dict[str, str]] = Field(default=None, description="环境变量")


class ExecuteResponse(BaseModel):
    """命令执行响应"""
    success: bool
    returncode: int
    stdout: str
    stderr: str
    duration: float
    error: Optional[str] = None


class InstallRequest(BaseModel):
    """工具安装请求"""
    tools: List[str] = Field(..., description="要安装的工具列表")
    update_cache: bool = Field(default=False, description="是否先更新 apt 缓存")


class InstallResponse(BaseModel):
    """工具安装响应"""
    success: bool
    installed: List[str]
    failed: List[str]
    already_installed: List[str]
    details: str


class ToolInfo(BaseModel):
    """工具信息"""
    name: str
    installed: bool
    version: Optional[str] = None
    path: Optional[str] = None


# ============= 工具管理 =============

# Kali 工具元包映射
KALI_METAPACKAGES = {
    "web": "kali-tools-web",
    "vulnerability": "kali-tools-vulnerability", 
    "information-gathering": "kali-tools-information-gathering",
    "passwords": "kali-tools-passwords",
    "wireless": "kali-tools-wireless",
    "forensics": "kali-tools-forensics",
    "sniffing": "kali-tools-sniffing-spoofing",
    "exploitation": "kali-tools-exploitation",
}

# 工具到包名的映射
TOOL_PACKAGES = {
    "nmap": ["nmap"],
    "masscan": ["masscan"],
    "nuclei": [],  # 特殊安装
    "nikto": ["nikto"],
    "dirb": ["dirb"],
    "gobuster": ["gobuster"],
    "wfuzz": ["wfuzz"],
    "ffuf": [],  # 特殊安装
    "sqlmap": ["sqlmap"],
    "sslscan": ["sslscan"],
    "testssl": [],  # 特殊安装
    "whatweb": ["whatweb"],
    "wafw00f": ["wafw00f"],
    "sublist3r": ["sublist3r"],
    "subfinder": [],  # 特殊安装
    "httpx": [],  # 特殊安装
    "amass": ["amass"],
    "dnsenum": ["dnsenum"],
    "fierce": ["fierce"],
    "theharvester": ["theharvester"],
    "maltego": ["maltego"],
    "recon-ng": ["recon-ng"],
    "hydra": ["hydra"],
    "john": ["john"],
    "hashcat": ["hashcat"],
    "metasploit": ["metasploit-framework"],
    "burpsuite": ["burpsuite"],
    "zaproxy": ["zaproxy"],
    "wireshark": ["wireshark"],
    "tshark": ["tshark"],
    "tcpdump": ["tcpdump"],
    "aircrack-ng": ["aircrack-ng"],
}

# 安装状态缓存
_tool_cache: Dict[str, bool] = {}
_install_lock = asyncio.Lock()


def is_tool_installed(tool_name: str) -> bool:
    """检查工具是否已安装"""
    if tool_name in _tool_cache:
        return _tool_cache[tool_name]
    
    result = shutil.which(tool_name) is not None
    _tool_cache[tool_name] = result
    return result


def get_tool_version(tool_name: str) -> Optional[str]:
    """获取工具版本"""
    try:
        # 尝试常见的版本命令
        for flag in ["--version", "-v", "-V", "version"]:
            proc = asyncio.create_subprocess_exec(
                tool_name, flag,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = asyncio.run(asyncio.wait_for(proc.communicate(), timeout=5))
            if stdout:
                version = stdout.decode().split('\n')[0]
                return version[:100]
    except:
        pass
    return None


async def install_apt_packages(packages: List[str], update_cache: bool = False) -> tuple[bool, str]:
    """安装 APT 包"""
    if not packages:
        return True, "No packages to install"
    
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    
    try:
        # 更新缓存
        if update_cache:
            logger.info("Updating apt cache...")
            proc = await asyncio.create_subprocess_exec(
                "apt-get", "update",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)
        
        # 安装包
        logger.info(f"Installing packages: {packages}")
        cmd = ["apt-get", "install", "-y", "--no-install-recommends"] + packages
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
        
        if proc.returncode == 0:
            return True, stdout.decode()
        else:
            return False, stderr.decode()
    
    except asyncio.TimeoutError:
        return False, "Installation timeout"
    except Exception as e:
        return False, str(e)


async def install_special_tool(tool_name: str) -> tuple[bool, str]:
    """安装需要特殊处理的工具"""
    try:
        if tool_name == "nuclei":
            # 安装 nuclei
            cmd = [
                "sh", "-c",
                "curl -sSL https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_$(uname -s)_$(uname -m).zip -o /tmp/nuclei.zip && "
                "unzip -o /tmp/nuclei.zip -d /usr/local/bin/ && "
                "chmod +x /usr/local/bin/nuclei && "
                "rm /tmp/nuclei.zip && "
                "nuclei -update-templates"
            ]
        elif tool_name == "ffuf":
            cmd = [
                "sh", "-c",
                "curl -sSL https://github.com/ffuf/ffuf/releases/latest/download/ffuf_2.1.0_linux_amd64.tar.gz | "
                "tar -xzf - -C /usr/local/bin/ && "
                "chmod +x /usr/local/bin/ffuf"
            ]
        elif tool_name == "httpx":
            cmd = [
                "sh", "-c",
                "curl -sSL https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_$(uname -s)_$(uname -m).zip -o /tmp/httpx.zip && "
                "unzip -o /tmp/httpx.zip -d /usr/local/bin/ && "
                "chmod +x /usr/local/bin/httpx && "
                "rm /tmp/httpx.zip"
            ]
        elif tool_name == "subfinder":
            cmd = [
                "sh", "-c",
                "curl -sSL https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_$(uname -s)_$(uname -m).zip -o /tmp/subfinder.zip && "
                "unzip -o /tmp/subfinder.zip -d /usr/local/bin/ && "
                "chmod +x /usr/local/bin/subfinder && "
                "rm /tmp/subfinder.zip"
            ]
        elif tool_name == "testssl":
            cmd = [
                "sh", "-c",
                "git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl && "
                "ln -sf /opt/testssl/testssl.sh /usr/local/bin/testssl"
            ]
        else:
            return False, f"Unknown special tool: {tool_name}"
        
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
        
        if proc.returncode == 0:
            return True, stdout.decode()
        else:
            return False, stderr.decode()
    
    except Exception as e:
        return False, str(e)


# ============= API 端点 =============

@app.get("/health")
async def health_check():
    """健康检查"""
    return {"status": "healthy", "service": "kali-scanner"}


@app.post("/execute", response_model=ExecuteResponse)
async def execute_command(request: ExecuteRequest):
    """执行命令"""
    logger.info(f"Executing command: {request.command} {' '.join(request.args)}")
    
    start_time = datetime.now()
    
    try:
        # 构建环境变量
        env = os.environ.copy()
        if request.env:
            env.update(request.env)
        
        # 执行命令
        proc = await asyncio.create_subprocess_exec(
            request.command,
            *request.args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=request.cwd,
            env=env
        )
        
        # 等待执行完成
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=request.timeout
        )
        
        duration = (datetime.now() - start_time).total_seconds()
        
        return ExecuteResponse(
            success=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=stdout.decode('utf-8', errors='replace'),
            stderr=stderr.decode('utf-8', errors='replace'),
            duration=duration
        )
    
    except asyncio.TimeoutError:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Command timeout: {request.command}")
        return ExecuteResponse(
            success=False,
            returncode=-1,
            stdout="",
            stderr="",
            duration=duration,
            error=f"Command timeout after {request.timeout}s"
        )
    
    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Command execution error: {e}")
        return ExecuteResponse(
            success=False,
            returncode=-1,
            stdout="",
            stderr="",
            duration=duration,
            error=str(e)
        )


@app.post("/install", response_model=InstallResponse)
async def install_tools(request: InstallRequest):
    """安装工具"""
    logger.info(f"Installing tools: {request.tools}")
    
    async with _install_lock:
        installed = []
        failed = []
        already_installed = []
        details_list = []
        
        # 检查已安装
        for tool in request.tools:
            if is_tool_installed(tool):
                already_installed.append(tool)
        
        # 需要安装的工具
        to_install = [t for t in request.tools if t not in already_installed]
        
        if not to_install:
            return InstallResponse(
                success=True,
                installed=[],
                failed=[],
                already_installed=already_installed,
                details="All tools already installed"
            )
        
        # 收集 APT 包
        apt_packages = []
        special_tools = []
        
        for tool in to_install:
            packages = TOOL_PACKAGES.get(tool, [])
            if packages:
                apt_packages.extend(packages)
            else:
                special_tools.append(tool)
        
        # 去重
        apt_packages = list(set(apt_packages))
        
        # 安装 APT 包
        if apt_packages:
            success, output = await install_apt_packages(apt_packages, request.update_cache)
            details_list.append(f"APT install: {output[:500]}")
            
            if success:
                for tool in to_install:
                    if TOOL_PACKAGES.get(tool):
                        _tool_cache.pop(tool, None)
                        if is_tool_installed(tool):
                            installed.append(tool)
                        else:
                            failed.append(tool)
            else:
                failed.extend([t for t in to_install if TOOL_PACKAGES.get(t)])
        
        # 安装特殊工具
        for tool in special_tools:
            success, output = await install_special_tool(tool)
            details_list.append(f"{tool}: {output[:200]}")
            
            _tool_cache.pop(tool, None)
            if success and is_tool_installed(tool):
                installed.append(tool)
            else:
                failed.append(tool)
        
        return InstallResponse(
            success=len(failed) == 0,
            installed=installed,
            failed=failed,
            already_installed=already_installed,
            details="\n".join(details_list)
        )


@app.get("/tools", response_model=List[ToolInfo])
async def list_tools(filter: Optional[str] = None):
    """列出工具状态"""
    tools = []
    
    # 检查所有已知工具
    tool_list = list(TOOL_PACKAGES.keys())
    if filter:
        tool_list = [t for t in tool_list if filter.lower() in t.lower()]
    
    for tool_name in tool_list:
        installed = is_tool_installed(tool_name)
        version = get_tool_version(tool_name) if installed else None
        path = shutil.which(tool_name) if installed else None
        
        tools.append(ToolInfo(
            name=tool_name,
            installed=installed,
            version=version,
            path=path
        ))
    
    return tools


@app.get("/tools/{tool_name}", response_model=ToolInfo)
async def get_tool_info(tool_name: str):
    """获取单个工具信息"""
    installed = is_tool_installed(tool_name)
    version = get_tool_version(tool_name) if installed else None
    path = shutil.which(tool_name) if installed else None
    
    return ToolInfo(
        name=tool_name,
        installed=installed,
        version=version,
        path=path
    )


# ============= 启动服务 =============

if __name__ == "__main__":
    logger.info("Starting Kali Scanner Service...")
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8888,
        log_level="info"
    )
