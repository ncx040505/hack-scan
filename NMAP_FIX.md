# Nmap 目标参数修复 ✅

## 问题描述

AI Agent 在调用 nmap 工具时，传递的参数格式如下：
```json
{
  "target": "10.0.5.11",
  "args": "-p- -sV -sC -T4"
}
```

但在 `NmapTool.execute()` 方法中，当使用 `args` 参数时，只执行了：
```python
return await _run_shell_command(f"nmap {args}", timeout)
```

**结果**：实际执行的命令是 `nmap -p- -sV -sC -T4`，**缺少目标参数**，导致：
```
Nmap done: 0 IP addresses (0 hosts up) scanned in 0.08 seconds
```

## 修复方案

修改 `backend/llm/tools.py` 中的 `NmapTool.execute()` 方法：

### 修复前
```python
if args:
    if "-Pn" not in args and "-pn" not in args.lower():
        args = f"-Pn {args}"
    return await _run_shell_command(f"nmap {args}", timeout)
```

### 修复后
```python
if args:
    # 确保 target 参数被包含
    if not target:
        return ToolResult(success=False, output="", error="缺少必需参数: target")
    
    # 自动添加 -Pn 跳过主机发现
    if "-Pn" not in args and "-pn" not in args.lower():
        args = f"-Pn {args}"
    
    # 将 target 添加到命令末尾
    full_cmd = f"nmap {args} {target}"
    return await _run_shell_command(full_cmd, timeout)
```

## 测试结果

### 测试1：使用 args + target 参数
```python
result = await tool.execute(
    target="127.0.0.1",
    args="-p- -sV -sC -T4"
)
```

**结果**：
```
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-05 13:35 EDT
Nmap scan report for localhost (127.0.0.1)
Host is up (0.0000020s latency).
...
✅ 目标地址已正确传递
```

### 测试2：标准参数模式
```python
result = await tool.execute(
    target="127.0.0.1",
    ports="22,80,443",
    options="-sV"
)
```

**结果**：✅ 正常工作

## 影响范围

- ✅ **AI Agent 调用 nmap**：现在可以正确传递目标
- ✅ **保持向后兼容**：标准参数模式不受影响
- ✅ **自动添加 -Pn**：避免 ICMP 被过滤导致的扫描失败

## 相关文件

- `backend/llm/tools.py` - 修复位置

## 额外优化

自动添加 `-Pn` 参数（跳过主机发现），避免以下常见问题：
- ICMP 被防火墙过滤
- 目标不响应 ping
- 扫描显示 "0 hosts up"

## 验证

运行测试脚本：
```bash
python3 /tmp/test_nmap_fix.py
```

预期结果：
- ✅ 目标地址包含在扫描输出中
- ✅ 扫描成功执行
- ✅ 返回有效结果
