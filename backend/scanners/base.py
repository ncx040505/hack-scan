"""Base scanner interface"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import AsyncIterator


class ScannerType(str, Enum):
    NMAP = "nmap"
    NUCLEI = "nuclei"
    WEB = "web"
    CUSTOM = "custom"


@dataclass
class ScanFinding:
    """扫描发现的统一数据结构"""
    scanner: ScannerType
    name: str
    severity: str  # critical, high, medium, low, info
    category: str
    description: str
    location: str  # URL/IP:Port/File path
    evidence: str = ""
    raw_data: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


class BaseScanner(ABC):
    """扫描器基类"""
    
    scanner_type: ScannerType
    
    @abstractmethod
    async def scan(self, target: str, config: dict) -> AsyncIterator[ScanFinding]:
        """执行扫描，yield 发现的问题"""
        pass
    
    @abstractmethod
    async def is_available(self) -> bool:
        """检查扫描器是否可用"""
        pass
    
    def validate_target(self, target: str) -> bool:
        """验证目标格式"""
        # 基础验证，子类可覆盖
        return bool(target and len(target) < 500)
