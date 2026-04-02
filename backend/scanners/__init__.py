"""Scanner factory and orchestration"""
from .base import BaseScanner, ScannerType
from .nmap_scanner import NmapScanner
from .nuclei_scanner import NucleiScanner


def get_scanner(scanner_type: ScannerType) -> BaseScanner:
    """获取扫描器实例"""
    scanners = {
        ScannerType.NMAP: NmapScanner,
        ScannerType.NUCLEI: NucleiScanner,
    }
    
    if scanner_type not in scanners:
        raise ValueError(f"Unknown scanner type: {scanner_type}")
    
    return scanners[scanner_type]()


async def get_available_scanners() -> list[ScannerType]:
    """获取可用的扫描器列表"""
    available = []
    
    for scanner_type in ScannerType:
        if scanner_type == ScannerType.CUSTOM:
            continue
        try:
            scanner = get_scanner(scanner_type)
            if await scanner.is_available():
                available.append(scanner_type)
        except Exception:
            pass
    
    return available
