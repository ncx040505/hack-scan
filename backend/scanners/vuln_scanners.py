"""漏洞扫描与组件分析类扫描器"""
import re
import json
from typing import AsyncIterator, List

from loguru import logger
from .base import ScannerType, ScanFinding
from .kali_scanner import KaliBaseScanner


class KaliWapitiScanner(KaliBaseScanner):
    """Wapiti Web 漏洞扫描器"""
    scanner_type = ScannerType.WAPITI
    
    def get_tool_name(self) -> str:
        return "wapiti"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [
            "-u", target,
            "-f", "json",
            "-o", "/dev/stdout",
            "-m", "common", "blindsql", "xss", "exec", "file", "sql",
            "--no-verify",
            "--timeout", "10"
        ]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for vuln_type, vulns in data.get("vulnerabilities", {}).items():
                for vuln in vulns:
                    severity_map = {"High": "high", "Medium": "medium", "Low": "low", "Information": "info"}
                    severity = severity_map.get(vuln.get("level", ""), "medium")
                    
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"Wapiti: {vuln_type} - {vuln.get('info', '')[:60]}",
                        severity=severity,
                        category="web_vulnerability",
                        description=vuln.get("info", ""),
                        location=vuln.get("path", target),
                        evidence=vuln.get("payload", ""),
                        raw_data=vuln
                    )
        except json.JSONDecodeError:
            # 文本解析后备
            for line in stdout.split('\n'):
                if 'vulnerability' in line.lower() or 'vuln' in line.lower():
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"Wapiti 发现: {line[:60]}",
                        severity="medium",
                        category="web_vulnerability",
                        description=line,
                        location=target,
                        raw_data={"raw": line}
                    )


class KaliTrivyScanner(KaliBaseScanner):
    """Trivy 容器/文件系统漏洞扫描器"""
    scanner_type = ScannerType.TRIVY
    
    def get_tool_name(self) -> str:
        return "trivy"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        scan_type = config.get("trivy_type", "fs")  # fs, image, repo
        severity = config.get("trivy_severity", "CRITICAL,HIGH,MEDIUM")
        
        args = [scan_type, "--format", "json", "--severity", severity]
        
        if scan_type == "image":
            args.append(target)
        else:
            args.extend(["--scanners", "vuln", target])
        
        return args
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for result in data.get("Results", []):
                for vuln in result.get("Vulnerabilities", []):
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"{vuln.get('VulnerabilityID', 'N/A')}: {vuln.get('PkgName', '')}",
                        severity=vuln.get("Severity", "medium").lower(),
                        category="dependency_vulnerability",
                        description=vuln.get("Description", "")[:500],
                        location=f"{result.get('Target', target)} - {vuln.get('PkgName')}",
                        evidence=f"Installed: {vuln.get('InstalledVersion')}, Fixed: {vuln.get('FixedVersion', 'N/A')}",
                        raw_data=vuln
                    )
        except json.JSONDecodeError:
            pass


class KaliGrypeScanner(KaliBaseScanner):
    """Grype 依赖漏洞扫描器"""
    scanner_type = ScannerType.GRYPE
    
    def get_tool_name(self) -> str:
        return "grype"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return [target, "-o", "json", "--only-fixed"]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for match in data.get("matches", []):
                vuln = match.get("vulnerability", {})
                artifact = match.get("artifact", {})
                
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"{vuln.get('id', 'N/A')}: {artifact.get('name', '')}",
                    severity=vuln.get("severity", "medium").lower(),
                    category="dependency_vulnerability",
                    description=vuln.get("description", "")[:500],
                    location=f"{artifact.get('name')} {artifact.get('version')}",
                    evidence=f"Fix: {vuln.get('fix', {}).get('versions', ['N/A'])}",
                    raw_data=match
                )
        except json.JSONDecodeError:
            pass


class KaliLynisScanner(KaliBaseScanner):
    """Lynis 系统安全审计"""
    scanner_type = ScannerType.LYNIS
    
    def get_tool_name(self) -> str:
        return "lynis"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        return ["audit", "system", "--quick", "--no-colors", "--json"]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for test in data.get("tests", []):
                status = test.get("status", "")
                if status in ["warning", "suggestion"]:
                    severity = "medium" if status == "warning" else "low"
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"Lynis: {test.get('id', '')} - {test.get('description', '')[:60]}",
                        severity=severity,
                        category="system_hardening",
                        description=test.get("description", ""),
                        location=target,
                        evidence=test.get("solution", ""),
                        raw_data=test
                    )
        except json.JSONDecodeError:
            for line in stdout.split('\n'):
                if 'WARNING' in line or 'SUGGESTION' in line:
                    severity = "medium" if 'WARNING' in line else "low"
                    yield ScanFinding(
                        scanner=self.scanner_type,
                        name=f"Lynis: {line.strip()[:60]}",
                        severity=severity,
                        category="system_hardening",
                        description=line.strip(),
                        location=target,
                        raw_data={"raw": line}
                    )


class KaliSearchsploitScanner(KaliBaseScanner):
    """SearchSploit 漏洞利用数据库搜索"""
    scanner_type = ScannerType.SEARCHSPLOIT
    
    def get_tool_name(self) -> str:
        return "searchsploit"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        search_terms = config.get("searchsploit_terms", target)
        return [search_terms, "--json", "-t"]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        try:
            data = json.loads(stdout) if stdout.strip() else {}
            for exploit in data.get("RESULTS_EXPLOIT", []):
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"Exploit: {exploit.get('Title', '')[:60]}",
                    severity="high",
                    category="exploit_available",
                    description=f"EDB-ID: {exploit.get('EDB-ID')}, 作者: {exploit.get('Author')}",
                    location=exploit.get("Path", ""),
                    evidence=f"平台: {exploit.get('Platform')}, 类型: {exploit.get('Type')}",
                    raw_data=exploit
                )
        except json.JSONDecodeError:
            for line in stdout.split('\n'):
                if '|' in line and 'Exploit' not in line:
                    parts = [p.strip() for p in line.split('|')]
                    if len(parts) >= 2:
                        yield ScanFinding(
                            scanner=self.scanner_type,
                            name=f"Exploit: {parts[0][:60]}",
                            severity="medium",
                            category="exploit_available",
                            description=parts[0],
                            location=target,
                            raw_data={"raw": line}
                        )


class KaliYaraScanner(KaliBaseScanner):
    """YARA 恶意软件/规则匹配扫描器"""
    scanner_type = ScannerType.YARA
    
    def get_tool_name(self) -> str:
        return "yara"
    
    def build_command_args(self, target: str, config: dict) -> List[str]:
        rules_path = config.get("yara_rules", "/usr/share/yara-rules/")
        return ["-r", "-s", rules_path, target]
    
    async def parse_output(self, stdout: str, stderr: str, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        for line in stdout.split('\n'):
            if not line.strip() or line.startswith('error:'):
                continue
            match = re.match(r'(\S+)\s+(.+)', line)
            if match:
                rule_name = match.group(1)
                matched_file = match.group(2)
                yield ScanFinding(
                    scanner=self.scanner_type,
                    name=f"YARA 匹配: {rule_name}",
                    severity="high",
                    category="malware_detection",
                    description=f"YARA 规则 {rule_name} 匹配到文件 {matched_file}",
                    location=matched_file,
                    evidence=line,
                    raw_data={"rule": rule_name, "file": matched_file}
                )
