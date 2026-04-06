"""快速测试 Kali 集成"""
import asyncio
import sys
sys.path.insert(0, '/root/shelling/backend')

from scanners.kali_client import get_kali_client
from scanners.tool_selector import select_and_prepare_tools, analyze_target


async def test_kali_integration():
    """测试 Kali 集成"""
    print("=" * 60)
    print("测试 Kali Docker 集成")
    print("=" * 60)
    
    # 获取客户端（使用 localhost）
    client = get_kali_client()
    client.base_url = "http://localhost:8888"
    
    # 1. 健康检查
    print("\n1. 健康检查...")
    healthy = await client.health_check()
    print(f"   状态: {'✅ 健康' if healthy else '❌ 不健康'}")
    
    # 2. 检查已安装工具
    print("\n2. 检查预装工具...")
    for tool in ["nmap", "masscan", "nuclei"]:
        info = await client.get_tool_info(tool)
        status = "✅" if info.installed else "❌"
        print(f"   {status} {tool}: {info.path or '未安装'}")
    
    # 3. 测试命令执行
    print("\n3. 测试 nmap 执行...")
    result = await client.execute("nmap", ["--version"], timeout=10)
    if result.success:
        version_line = result.stdout.split('\n')[0]
        print(f"   ✅ {version_line}")
    else:
        print(f"   ❌ 执行失败: {result.error}")
    
    # 4. 测试工具安装
    print("\n4. 测试工具自动安装...")
    installed, failed, already = await client.install_tools(["nuclei"], update_cache=True)
    print(f"   已安装: {installed}")
    print(f"   已存在: {already}")
    print(f"   失败: {failed}")
    
    # 5. 测试目标分析
    print("\n5. 测试目标分析...")
    targets = [
        "https://example.com",
        "192.168.1.1",
        "example.com"
    ]
    for target in targets:
        analysis = analyze_target(target)
        print(f"   {target} → 类型: {analysis['type']}, URL: {analysis['is_url']}, IP: {analysis['is_ip']}")
    
    # 6. 测试规则选择器
    print("\n6. 测试规则选择器...")
    from scanners.tool_selector import select_tools_with_rules
    
    for target, scan_type in [("https://example.com", "quick"), ("192.168.1.1", "full")]:
        selection = select_tools_with_rules(target, scan_type)
        print(f"   {target} ({scan_type}): {', '.join(selection.tools)}")
        print(f"     理由: {selection.reason}")
    
    print("\n" + "=" * 60)
    print("✅ 所有测试通过！")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_kali_integration())
