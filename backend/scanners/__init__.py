"""Scanner factory and orchestration"""
from pathlib import Path
from loguru import logger
from sqlalchemy import select, cast, String, func

from app.core.database import AsyncSessionLocal
from app.models.database import SecurityTool
from .base import BaseScanner, ScannerType
from .kali_scanner import KaliNmapScanner, KaliNucleiScanner


def get_scanner(scanner_type: ScannerType) -> BaseScanner:
    """获取扫描器实例"""
    scanners = {
        ScannerType.NMAP: KaliNmapScanner,
        ScannerType.NUCLEI: KaliNucleiScanner,
    }
    
    if scanner_type not in scanners:
        raise ValueError(f"Unknown scanner type: {scanner_type}")
    
    return scanners[scanner_type]()


async def _get_uploaded_scanners() -> list[str]:
    """获取已上传的扫描器名称"""
    scanners: list[str] = []
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(SecurityTool.name, SecurityTool.file_path, SecurityTool.is_enabled)
                .where(func.lower(cast(SecurityTool.tool_type, String)) == "scanner")
            )
            for name, file_path, is_enabled in result.all():
                if not is_enabled:
                    continue
                if file_path and Path(file_path).exists():
                    scanners.append(name)
    except Exception as exc:
        logger.warning(f"Failed to load uploaded scanners: {exc}")
    return scanners


async def get_available_scanners() -> tuple[list[ScannerType], list[str]]:
    """获取可用的扫描器列表"""
    available: list[ScannerType] = []
    
    for scanner_type in ScannerType:
        if scanner_type == ScannerType.CUSTOM:
            continue
        try:
            scanner = get_scanner(scanner_type)
            if await scanner.is_available():
                available.append(scanner_type)
        except Exception:
            pass
    
    uploaded = await _get_uploaded_scanners()
    return available, uploaded
