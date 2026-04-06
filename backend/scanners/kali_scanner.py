"""Generic Kali-based scanner - 通过 Kali 容器执行扫描工具"""
import asyncio
import json
import re
from typing import AsyncIterator, List, Dict, Optional
from abc import ABC, abstractmethod

from loguru import logger

from .base import BaseScanner, ScanFinding, ScannerType
from .kali_client import get_kali_client, KaliClient


class KaliBaseScanner(BaseScanner, ABC):
    """基于 Kali 容器的扫描器基类"""
    
    def __init__(self):
        self.kali_client: KaliClient = get_kali_client()
    
    @abstractmethod
    def get_tool_name(self) -> str:
        """获取工具名称"""
        pass
    
    @abstractmethod
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建命令参数"""
        pass
    
    @abstractmethod
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析输出"""
        pass
    
    async def is_available(self) -> bool:
        """检查工具是否可用"""
        try:
            # 检查 Kali 容器健康状态
            if not await self.kali_client.health_check():
                logger.warning("Kali scanner container is not healthy")
                return False
            
            # 检查工具是否已安装
            tool_name = self.get_tool_name()
            info = await self.kali_client.get_tool_info(tool_name)
            
            if not info.installed:
                logger.info(f"{tool_name} not installed in Kali container, will install on demand")
                # 返回 True，因为可以按需安装
                return True
            
            return True
        except Exception as e:
            logger.error(f"Failed to check {self.get_tool_name()} availability: {e}")
            return False
    
    async def scan(self, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        """执行扫描"""
        if not self.validate_target(target):
            raise ValueError(f"Invalid target: {target}")
        
        tool_name = self.get_tool_name()
        
        # 确保工具已安装
        logger.info(f"Ensuring {tool_name} is installed in Kali container...")
        await self.kali_client.ensure_tools_installed([tool_name])
        
        # 构建命令
        args = self.build_command_args(target, config)
        
        logger.info(f"Executing {tool_name} in Kali: {' '.join(args)}")
        
        # 执行扫描
        timeout = config.get("scan_timeout", 600)
        result = await self.kali_client.execute(
            command=tool_name,
            args=args,
            timeout=timeout
        )
        
        if not result.success and result.returncode != 0:
            # 某些扫描工具即使发现漏洞也会返回非零
            logger.warning(
                f"{tool_name} returned code {result.returncode}, "
                f"but will try to parse output anyway"
            )
        
        # 解析输出
        async for finding in self.parse_output(
            result.stdout,
            result.stderr,
            target,
            config
        ):
            yield finding


class KaliNmapScanner(KaliBaseScanner):
    """Nmap 扫描器（通过 Kali 容器）"""
    
    scanner_type = ScannerType.NMAP
    
    def get_tool_name(self) -> str:
        return "nmap"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建 Nmap 命令参数"""
        ports = config.get("custom_ports", [])
        if ports:
            port_str = ",".join(map(str, ports))
        else:
            # 默认扫描常见端口
            port_str = "1-1000"
        
        args = [
            "-sV",  # 服务版本检测
            "-sC",  # 默认脚本扫描
            "--open",  # 只显示开放端口
            "-T4",  # 快速模式
            "-p", port_str,
            "-oX", "-",  # XML 输出到 stdout
            target
        ]
        
        return args
    
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析 Nmap XML 输出"""
        import xml.etree.ElementTree as ET
        
        try:
            root = ET.fromstring(stdout)
        except ET.ParseError as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
            logger.debug(f"Stdout: {stdout[:500]}")
            return
        
        for host in root.findall(".//host"):
            addr = host.find("address")
            ip = addr.get("addr") if addr is not None else target
            
            for port in host.findall(".//port"):
                portid = port.get("portid")
                protocol = port.get("protocol", "tcp")
                
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                
                service = port.find("service")
                service_name = service.get("name", "unknown") if service is not None else "unknown"
                version = service.get("version", "") if service is not None else ""
                product = service.get("product", "") if service is not None else ""
                
                # 构建服务描述
                desc_parts = [f"端口 {portid}/{protocol} 开放"]
                if product:
                    desc_parts.append(f"服务: {product}")
                if version:
                    desc_parts.append(f"版本: {version}")
                
                # 检查脚本输出（可能包含漏洞信息）
                scripts = port.findall(".//script")
                vuln_scripts = []
                for script in scripts:
                    script_id = script.get("id", "")
                    script_output = script.get("output", "")
                    
                    # 标记可能的漏洞脚本
                    if any(keyword in script_id.lower() for keyword in ["vuln", "exploit", "cve"]):
                        vuln_scripts.append(f"{script_id}: {script_output[:200]}")
                
                severity = "info"
                category = "open_port"
                
                # 根据服务判断严重性
                if vuln_scripts:
                    severity = "medium"
                    category = "potential_vulnerability"
                    desc_parts.extend(vuln_scripts)
                elif service_name in ["telnet", "ftp", "smtp", "http"]:
                    severity = "low"
                    category = "insecure_service"
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"开放端口: {portid}/{protocol} - {service_name}",
                    severity=severity,
                    category=category,
                    description="\n".join(desc_parts),
                    location=f"{ip}:{portid}",
                    evidence=f"{service_name} {version}".strip(),
                    raw_data={
                        "port": portid,
                        "protocol": protocol,
                        "service": service_name,
                        "version": version,
                        "product": product,
                    }
                )


class KaliNucleiScanner(KaliBaseScanner):
    """Nuclei 扫描器（通过 Kali 容器）"""
    
    scanner_type = ScannerType.NUCLEI
    
    def get_tool_name(self) -> str:
        return "nuclei"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        """构建 Nuclei 命令参数"""
        args = [
            "-u", target,
            "-json",  # JSON 输出
            "-silent",  # 静默模式
        ]
        
        # 严重等级过滤
        severity = config.get("nuclei_severity", "critical,high,medium")
        if severity:
            args.extend(["-severity", severity])
        
        # 速率限制
        rate_limit = config.get("rate_limit", 150)
        args.extend(["-rate-limit", str(rate_limit)])
        
        return args
    
    async def parse_output(
        self,
        stdout: str,
        stderr: str,
        target: str,
        config: dict
    ) -> AsyncIterator[ScanFinding]:
        """解析 Nuclei JSON 输出"""
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            
            try:
                result = json.loads(line)
            except json.JSONDecodeError:
                continue
            
            info = result.get("info", {})
            template_id = result.get("template-id", "unknown")
            name = info.get("name", template_id)
            severity = info.get("severity", "info").lower()
            description = info.get("description", "")
            matched_at = result.get("matched-at", target)
            
            # 提取证据
            extracted_results = result.get("extracted-results", [])
            matcher_name = result.get("matcher-name", "")
            evidence_parts = []
            
            if matcher_name:
                evidence_parts.append(f"Matcher: {matcher_name}")
            if extracted_results:
                evidence_parts.append(f"Extracted: {', '.join(extracted_results[:3])}")
            
            yield ScanFinding(
                scanner=self.scanner_type,
                name=name,
                severity=severity,
                category=info.get("tags", ["nuclei"])[0] if info.get("tags") else "nuclei",
                description=description or f"Nuclei 模板 {template_id} 匹配",
                location=matched_at,
                evidence="\n".join(evidence_parts) if evidence_parts else "",
                raw_data=result
            )
