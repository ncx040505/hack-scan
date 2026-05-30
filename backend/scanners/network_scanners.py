"""网络扫描与资产识别类扫描器"""
import re
import json
import xml.etree.ElementTree as ET
from typing import AsyncIterator, List

from loguru import logger
from .base import ScannerType, ScanFinding
from .kali_scanner import KaliBaseScanner


class KaliMasscanScanner(KaliBaseScanner):
    """Masscan 快速端口扫描器"""
    scanner_type = ScannerType.MASSCAN
    
    def get_tool_name(self) -> str:
        return "masscan"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        ports = config.get("custom_ports", "1-1000")
        rate = config.get("masscan_rate", 1000)
        return [
            target,
            "-p", str(ports),
            "--rate", str(rate),
            "--open",
            "-oJ", "/dev/stdout"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.strip().split('\n'):
            line = line.strip().rstrip(',')
            if not line or line in ['[', ']']:
                continue
            try:
                data = json.loads(line)
                for port_info in data.get("ports", []):
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"开放端口: {port_info.get('port')}/{port_info.get('proto', 'tcp')}",
                        severity="info",
                        category="network",
                        description=f"Masscan 发现端口 {port_info.get('port')} 开放",
                        location=f"{data.get('ip', target)}:{port_info.get('port')}",
                        raw_data=data
                    )
            except json.JSONDecodeError:
                continue


class KaliNaabuScanner(KaliBaseScanner):
    """Naabu 端口扫描器"""
    scanner_type = ScannerType.NAABU
    
    def get_tool_name(self) -> str:
        return "naabu"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        ports = config.get("custom_ports", "top-1000")
        return [
            "-host", target,
            "-ports", str(ports),
            "-silent",
            "-json"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"开放端口: {data.get('port')}/{data.get('proto', 'tcp')}",
                    severity="info",
                    category="network",
                    description=f"Naabu 发现端口 {data.get('port')} 开放",
                    location=f"{data.get('host', target)}:{data.get('port')}",
                    raw_data=data
                )
            except json.JSONDecodeError:
                continue


class KaliRustscanScanner(KaliBaseScanner):
    """RustScan 快速端口扫描器"""
    scanner_type = ScannerType.RUSTSCAN
    
    def get_tool_name(self) -> str:
        return "rustscan"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "-a", target,
            "--no-nmap",
            "-b", "500",
            "--json"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else []
            if isinstance(data, list):
                for item in data:
                    for port in item.get("ports", []):
                        yield ScanFinding(
                            scanner=self.scanner_type,
                            name=f"开放端口: {port.get('port')}",
                            severity="info",
                            category="network",
                            description=f"RustScan 发现端口 {port.get('port')} 开放",
                            location=f"{item.get('ip', target)}:{port.get('port')}",
                            raw_data=item
                        )
        except json.JSONDecodeError:
            for line in stdout.split('\n'):
                match = re.search(r'(\d+)/(?:tcp|udp)', line)
                if match:
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"开放端口: {match.group(1)}",
                        severity="info",
                        category="network",
                        description=f"RustScan 发现端口 {match.group(1)} 开放",
                        location=f"{target}:{match.group(1)}",
                        raw_data={"port": int(match.group(1))}
                    )


class KaliHttpxScanner(KaliBaseScanner):
    """httpx HTTP 探测器"""
    scanner_type = ScannerType.HTTPX
    
    def get_tool_name(self) -> str:
        return "httpx"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "-u", target,
            "-silent",
            "-json",
            "-status-code",
            "-content-length",
            "-title",
            "-tech-detect",
            "-follow-redirects"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                technologies = data.get("tech", [])
                status_code = data.get("status_code", 0)
                
                severity = "info"
                if status_code >= 500:
                    severity = "low"
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"HTTP 服务: {data.get('url', target)}",
                    severity=severity,
                    category="web_fingerprint",
                    description=f"状态码: {status_code}, 标题: {data.get('title', 'N/A')}, 技术栈: {', '.join(technologies[:5])}",
                    location=data.get("url", target),
                    evidence=f"Status: {status_code}, Length: {data.get('content_length')}",
                    raw_data=data
                )
            except json.JSONDecodeError:
                continue


class KaliKatanaScanner(KaliBaseScanner):
    """Katana 爬虫/链接发现"""
    scanner_type = ScannerType.KATANA
    
    def get_tool_name(self) -> str:
        return "katana"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        depth = config.get("katana_depth", 3)
        return [
            "-u", target,
            "-d", str(depth),
            "-silent",
            "-json",
            "-jc"  # 解析 JavaScript
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        urls_found = set()
        for line in stdout.strip().split('\n'):
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                url = data.get("url", "")
                if url and url not in urls_found:
                    urls_found.add(url)
                    # 检测敏感路径
                    severity = "info"
                    sensitive_patterns = ['admin', 'login', 'api', 'config', 'backup', '.env', '.git', 'debug', 'test']
                    if any(p in url.lower() for p in sensitive_patterns):
                        severity = "medium"
                    
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"URL 发现: {url[:80]}",
                        severity=severity,
                        category="url_discovery",
                        description=f"Katana 发现 URL: {url}",
                        location=url,
                        raw_data=data
                    )
            except json.JSONDecodeError:
                continue


class KaliArpscanScanner(KaliBaseScanner):
    """ARP 网络扫描器"""
    scanner_type = ScannerType.NMAP  # 复用 NMAP 类型
    
    def get_tool_name(self) -> str:
        return "arp-scan"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return ["-l", "-localnet"] if '/' not in target else [target]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split('\n'):
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]+)\s+(.*)', line)
            if match:
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"主机发现: {match.group(1)}",
                    severity="info",
                    category="network",
                    description=f"MAC: {match.group(2)}, 厂商: {match.group(3).strip()}",
                    location=match.group(1),
                    raw_data={"ip": match.group(1), "mac": match.group(2), "vendor": match.group(3).strip()}
                )
