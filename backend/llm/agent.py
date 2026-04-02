"""AI Security Agent - 自主决策的安全测试代理"""
import json
import re
from typing import Optional, Callable, Awaitable
from pydantic import BaseModel, Field
from langchain_openai import ChatOpenAI
from langchain_core.messages import HumanMessage, AIMessage, SystemMessage, ToolMessage
from loguru import logger

from app.core.config import get_settings
from app.core.database import AsyncSessionLocal
from llm.tools import get_tool, get_tools_schema, ToolResult
from llm.skill_loader import load_skills_from_db, execute_skill, get_skills_schema, SkillInfo
from llm.web_search import WebSearchTool, WEB_SEARCH_SCHEMA

settings = get_settings()


# ask_user 工具的 schema
ASK_USER_SCHEMA = {
    "name": "ask_user",
    "description": "向用户提问并等待回复。当你遇到问题需要用户决策、需要更多信息、或者需要用户确认时使用此工具。",
    "parameters": {
        "type": "object",
        "properties": {
            "question": {
                "type": "string",
                "description": "要问用户的问题"
            },
            "context": {
                "type": "string",
                "description": "问题的背景说明，帮助用户理解情况"
            },
            "options": {
                "type": "array",
                "items": {"type": "string"},
                "description": "可选的选项列表，如果问题有明确的选择"
            }
        },
        "required": ["question"]
    }
}


class AgentPauseException(Exception):
    """Agent 暂停异常，用于中断执行流程"""
    def __init__(self, question: str, context: str = None, options: list[str] = None, agent_state: dict = None):
        self.question = question
        self.context = context
        self.options = options
        self.agent_state = agent_state
        super().__init__(f"Agent paused: {question}")


class AgentThought(BaseModel):
    """Agent 思考过程"""
    analysis: str = Field(description="对当前情况的分析")
    plan: str = Field(description="下一步计划")
    tool_name: Optional[str] = Field(description="要调用的工具名称", default=None)
    tool_args: Optional[dict] = Field(description="工具参数", default=None)
    is_complete: bool = Field(description="是否完成测试", default=False)
    final_summary: Optional[str] = Field(description="最终总结", default=None)


class SecurityAgent:
    """AI 驱动的安全测试代理"""
    
    def __init__(
        self, 
        target: str,
        scan_context: dict,
        log_callback: Callable[[str, str, Optional[str], Optional[str]], Awaitable[None]] = None,
        max_iterations: int = 0,
        custom_prompt: str = None,
        llm_config: dict = None,
        search_config: dict = None,
        restored_state: dict = None,  # 从暂停状态恢复时传入
        session_factory = None  # 数据库会话工厂 (Celery 任务中必须传入)
    ):
        """
        Args:
            target: 扫描目标
            scan_context: 初始扫描结果上下文
            log_callback: 日志回调函数 (type, message, details, tool)
            max_iterations: 最大迭代次数，0 表示无限制
            custom_prompt: 用户自定义提示词
            llm_config: LLM 配置 (可选，否则使用数据库配置)
            search_config: 搜索配置 (可选，否则使用数据库配置)
            restored_state: 从暂停恢复时的 agent 状态
            session_factory: 数据库会话工厂 (用于 Celery 任务，避免事件循环冲突)
        """
        self.target = target
        self.scan_context = scan_context
        self.log_callback = log_callback
        self.max_iterations = max_iterations if max_iterations > 0 else 999999  # 无限制
        self.custom_prompt = custom_prompt
        self.llm_config = llm_config
        self.search_config = search_config
        self.restored_state = restored_state
        self.session_factory = session_factory or AsyncSessionLocal
        
        # LLM 在 run() 中初始化，以便加载数据库配置
        self.llm = None
        self.web_search = None
        
        self.messages = []
        self.findings = []
        self.tools_used = []
        self.skills: list[SkillInfo] = []  # 用户自定义 skill
        self.current_iteration = 0  # 当前迭代次数
    
    async def _log(self, log_type: str, message: str, details: str = None, tool: str = None):
        """记录日志"""
        if self.log_callback:
            await self.log_callback(log_type, message, details, tool)
    
    async def _init_llm(self):
        """初始化 LLM（从数据库加载配置）"""
        if self.llm_config:
            # 使用传入的配置
            config = self.llm_config
        else:
            # 从数据库加载配置
            from app.api.settings import get_active_llm_config
            async with self.session_factory() as db:
                db_config = await get_active_llm_config(db)
                if db_config:
                    config = {
                        'model': db_config.model,
                        'temperature': db_config.temperature / 100,
                        'api_key': db_config.api_key,
                        'base_url': db_config.api_base_url,
                        'max_tokens': db_config.max_tokens,
                    }
                    await self._log("info", f"🤖 使用 LLM 配置: {db_config.name}", 
                                  f"模型: {db_config.model}")
                else:
                    # 使用环境变量默认配置
                    config = {
                        'model': settings.llm_model,
                        'temperature': settings.llm_temperature,
                        'api_key': settings.openai_api_key,
                        'base_url': settings.openai_base_url,
                    }
                    await self._log("info", f"🤖 使用默认 LLM 配置", f"模型: {settings.llm_model}")
        
        self.llm = ChatOpenAI(
            model=config.get('model', 'gpt-4o'),
            temperature=config.get('temperature', 0.2),
            api_key=config.get('api_key') or None,
            base_url=config.get('base_url') or None,
            max_tokens=config.get('max_tokens', 4096),
        )
    
    async def _init_search(self):
        """初始化联网搜索工具"""
        if self.search_config:
            config = self.search_config
        else:
            # 从数据库加载配置
            from app.api.settings import get_search_settings_from_db
            async with self.session_factory() as db:
                search_settings = await get_search_settings_from_db(db)
                config = {
                    'enabled': search_settings.enabled,
                    'provider': search_settings.provider,
                    'api_key': search_settings.api_key,
                    'max_results': search_settings.max_results,
                }
        
        if config.get('enabled', True) and config.get('provider', 'none') != 'none':
            self.web_search = WebSearchTool(
                provider=config.get('provider', 'duckduckgo'),
                api_key=config.get('api_key'),
                max_results=config.get('max_results', 5)
            )
            await self._log("info", f"🌐 已启用联网搜索", f"提供商: {config.get('provider')}")
    
    async def _load_skills(self):
        """加载用户上传的 skills"""
        self.skills = await load_skills_from_db(self.session_factory)
        if self.skills:
            await self._log("info", f"📦 已加载 {len(self.skills)} 个用户 Skill", 
                          "\n".join([f"- {s.name}: {s.description}" for s in self.skills]))
    
    def _get_all_tools_schema(self) -> list[dict]:
        """获取所有工具（内置 + 用户 Skill + 搜索 + ask_user）的 Schema"""
        all_schemas = get_tools_schema()
        if self.skills:
            all_schemas.extend(get_skills_schema(self.skills))
        if self.web_search:
            all_schemas.append(WEB_SEARCH_SCHEMA)
        # 添加 ask_user 工具
        all_schemas.append(ASK_USER_SCHEMA)
        return all_schemas
    
    def _get_system_prompt(self) -> str:
        """获取系统提示词"""
        tools_desc = "\n".join([
            f"- {t['name']}: {t['description']}" 
            for t in self._get_all_tools_schema()
        ])
        
        base_prompt = f"""你是一名专业的渗透测试专家和安全研究员。你的任务是对目标进行全面的安全测试。

## 目标信息
- 目标: {self.target}

## 可用工具
{tools_desc}

## 工作方式
1. 分析当前掌握的信息
2. 决定下一步要执行的测试
3. 调用合适的工具
4. 分析工具输出，发现潜在问题
5. 重复以上步骤直到测试完成

## 输出格式
每次回复请使用以下 JSON 格式：
```json
{{
    "analysis": "对当前情况的分析",
    "plan": "下一步计划",
    "tool_name": "要调用的工具名称（可选）",
    "tool_args": {{"参数名": "参数值"}},
    "is_complete": false,
    "final_summary": null
}}
```

当你认为测试已经足够全面，设置 is_complete: true 并提供 final_summary。

## 注意事项
- 从侦察开始，逐步深入
- 根据发现调整测试策略
- 记录所有重要发现
- 不要执行破坏性操作
- 保持测试的合法性和道德性
- 当遇到问题需要用户决策、需要更多信息、或需要确认敏感操作时，使用 ask_user 工具向用户提问
"""
        
        # 添加用户自定义提示词
        if self.custom_prompt:
            base_prompt += f"""
## 用户额外要求
{self.custom_prompt}
"""
        
        return base_prompt

    def _parse_response(self, content: str) -> AgentThought:
        """解析 LLM 响应"""
        # 尝试提取 JSON 代码块
        json_match = re.search(r'```json\s*(.*?)\s*```', content, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                return AgentThought(**data)
            except Exception as e:
                logger.debug(f"Failed to parse JSON block: {e}")
        
        # 尝试查找 JSON 对象（从第一个 { 到最后一个 }）
        try:
            start = content.find('{')
            end = content.rfind('}')
            if start != -1 and end > start:
                json_str = content[start:end+1]
                data = json.loads(json_str)
                return AgentThought(**data)
        except Exception as e:
            logger.debug(f"Failed to parse JSON object: {e}")
        
        # 如果内容包含 is_complete: true 或类似模式，尝试提取
        if '"is_complete": true' in content or '"is_complete":true' in content:
            # 尝试提取 final_summary
            summary_match = re.search(r'"final_summary"\s*:\s*"([^"]*)"', content)
            summary = summary_match.group(1) if summary_match else content
            return AgentThought(
                analysis="测试完成",
                plan="",
                is_complete=True,
                final_summary=summary
            )
        
        # 解析失败，返回默认值，但不设置 is_complete=True，让 agent 继续尝试
        return AgentThought(
            analysis="响应格式异常，尝试重新解析",
            plan="请重新格式化响应",
            is_complete=False,
            tool_name=None,
            tool_args=None,
            final_summary=None
        )
    
    def _get_state(self) -> dict:
        """获取当前 agent 状态（用于暂停时保存）"""
        return {
            "messages": [
                {"type": m.__class__.__name__, "content": m.content}
                for m in self.messages
            ],
            "findings": self.findings,
            "tools_used": self.tools_used,
            "current_iteration": self.current_iteration,
            "target": self.target,
            "scan_context": self.scan_context,
            "custom_prompt": self.custom_prompt,
        }
    
    def _restore_state(self, state: dict):
        """从保存的状态恢复"""
        # 恢复消息
        self.messages = []
        for msg in state.get("messages", []):
            msg_type = msg["type"]
            content = msg["content"]
            if msg_type == "SystemMessage":
                self.messages.append(SystemMessage(content=content))
            elif msg_type == "HumanMessage":
                self.messages.append(HumanMessage(content=content))
            elif msg_type == "AIMessage":
                self.messages.append(AIMessage(content=content))
        
        # 恢复其他状态
        self.findings = state.get("findings", [])
        self.tools_used = state.get("tools_used", [])
        self.current_iteration = state.get("current_iteration", 0)

    async def run(self, user_reply: str = None) -> dict:
        """运行 Agent
        
        Args:
            user_reply: 用户回复（从暂停恢复时传入）
        
        Returns:
            执行结果，如果暂停会包含 paused=True 和 agent_state
        """
        await self._log("llm", "🤖 AI Agent 启动", f"目标: {self.target}")
        
        # 初始化 LLM 和搜索工具
        await self._init_llm()
        await self._init_search()
        
        # 加载用户自定义 skills
        await self._load_skills()
        
        # 检查是否从暂停状态恢复
        if self.restored_state:
            await self._log("info", "📥 从暂停状态恢复", f"继续执行第 {self.restored_state.get('current_iteration', 0)} 次迭代")
            self._restore_state(self.restored_state)
            
            # 添加用户回复
            if user_reply:
                self.messages.append(HumanMessage(content=f"""用户回复:
{user_reply}

请根据用户的回复继续执行测试。"""))
        else:
            # 初始化消息
            self.messages = [
                SystemMessage(content=self._get_system_prompt()),
                HumanMessage(content=f"""初始扫描结果:
{json.dumps(self.scan_context, ensure_ascii=False, indent=2)}

请分析以上信息，制定测试计划并开始执行。""")
            ]
        
        while self.current_iteration < self.max_iterations:
            self.current_iteration += 1
            await self._log("llm", f"🔄 迭代 {self.current_iteration}/{self.max_iterations}", "AI 正在思考...")
            
            try:
                # 调用 LLM
                response = await self.llm.ainvoke(self.messages)
                content = response.content
                
                # 记录 AI 原始响应
                logger.debug(f"Agent response: {content[:500]}...")
                
                # 解析响应
                thought = self._parse_response(content)
                
                # 记录思考过程
                await self._log(
                    "llm", 
                    f"💭 分析: {thought.analysis[:100]}...",
                    f"计划: {thought.plan}\n\n分析:\n{thought.analysis}"
                )
                
                # 检查是否完成
                if thought.is_complete:
                    await self._log("llm", "✅ AI 测试完成", thought.final_summary)
                    return {
                        "success": True,
                        "paused": False,
                        "findings": self.findings,
                        "tools_used": self.tools_used,
                        "iterations": self.current_iteration,
                        "summary": thought.final_summary
                    }
                
                # 执行工具
                if thought.tool_name and thought.tool_args:
                    try:
                        tool_result = await self._execute_tool(thought.tool_name, thought.tool_args)
                        
                        # 添加到消息历史
                        self.messages.append(AIMessage(content=content))
                        self.messages.append(HumanMessage(content=f"""工具 {thought.tool_name} 执行结果:
成功: {tool_result.success}
输出:
```
{tool_result.output[:3000]}
```
{f'错误: {tool_result.error}' if tool_result.error else ''}

请分析结果并决定下一步。"""))
                    except AgentPauseException as e:
                        # Agent 请求暂停
                        self.messages.append(AIMessage(content=content))
                        await self._log("info", "⏸️ AI Agent 暂停", f"等待用户回复: {e.question}")
                        return {
                            "success": True,
                            "paused": True,
                            "question": e.question,
                            "context": e.context,
                            "options": e.options,
                            "findings": self.findings,
                            "tools_used": self.tools_used,
                            "iterations": self.current_iteration,
                            "agent_state": self._get_state(),
                            "summary": None
                        }
                else:
                    # 没有工具调用，继续对话
                    self.messages.append(AIMessage(content=content))
                    self.messages.append(HumanMessage(content="请继续执行测试计划，调用合适的工具。"))
                    
            except AgentPauseException as e:
                # Agent 请求暂停（在 tool execution 之外）
                await self._log("info", "⏸️ AI Agent 暂停", f"等待用户回复: {e.question}")
                return {
                    "success": True,
                    "paused": True,
                    "question": e.question,
                    "context": e.context,
                    "options": e.options,
                    "findings": self.findings,
                    "tools_used": self.tools_used,
                    "iterations": self.current_iteration,
                    "agent_state": self._get_state(),
                    "summary": None
                }
            except Exception as e:
                logger.error(f"Agent iteration error: {e}")
                await self._log("error", f"❌ 迭代出错: {str(e)}")
                self.messages.append(HumanMessage(content=f"发生错误: {str(e)}，请继续。"))
        
        await self._log("llm", "⚠️ 达到最大迭代次数", f"已执行 {self.max_iterations} 次迭代")
        return {
            "success": True,
            "paused": False,
            "findings": self.findings,
            "tools_used": self.tools_used,
            "iterations": self.current_iteration,
            "summary": "达到最大迭代次数，测试终止"
        }

    async def _execute_tool(self, tool_name: str, tool_args: dict) -> ToolResult:
        """执行工具（包括用户 Skill 和搜索）"""
        await self._log("tool", f"🔧 调用工具: {tool_name}", json.dumps(tool_args, ensure_ascii=False, indent=2), tool_name)
        
        # 检查是否是 ask_user 工具
        if tool_name == "ask_user":
            return await self._execute_ask_user(tool_args)
        
        # 检查是否是用户 Skill (以 skill_ 前缀开头)
        if tool_name.startswith("skill_"):
            return await self._execute_skill(tool_name, tool_args)
        
        # 检查是否是联网搜索
        if tool_name == "web_search":
            return await self._execute_web_search(tool_args)
        
        tool = get_tool(tool_name)
        if not tool:
            result = ToolResult(success=False, output="", error=f"未知工具: {tool_name}")
            await self._log("error", f"❌ 工具不存在: {tool_name}", None, tool_name)
            return result
        
        # 确保工具已安装
        if not await tool.ensure_installed(self.log_callback):
            result = ToolResult(success=False, output="", error=f"工具 {tool_name} 安装失败")
            await self._log("error", f"❌ 工具安装失败: {tool_name}", None, tool_name)
            return result
        
        self.tools_used.append({"name": tool_name, "args": tool_args})
        
        try:
            result = await tool.execute(**tool_args)
            
            if result.success:
                await self._log(
                    "output", 
                    f"📤 {tool_name} 输出 ({len(result.output)} 字符)",
                    result.output[:2000] if result.output else "无输出",
                    tool_name
                )
            else:
                await self._log(
                    "error",
                    f"❌ {tool_name} 执行失败",
                    result.error,
                    tool_name
                )
            
            # 分析输出中的发现
            await self._analyze_output(tool_name, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Tool execution error: {e}")
            result = ToolResult(success=False, output="", error=str(e))
            await self._log("error", f"❌ {tool_name} 异常", str(e), tool_name)
            return result
    
    async def _execute_skill(self, tool_name: str, tool_args: dict) -> ToolResult:
        """执行用户自定义 Skill"""
        # 提取 skill 名称 (去掉 skill_ 前缀)
        skill_name = tool_name[6:]  # 移除 "skill_" 前缀
        
        # 查找对应的 skill
        skill = next((s for s in self.skills if s.name == skill_name), None)
        if not skill:
            result = ToolResult(success=False, output="", error=f"未找到 Skill: {skill_name}")
            await self._log("error", f"❌ Skill 不存在: {skill_name}", None, tool_name)
            return result
        
        self.tools_used.append({"name": tool_name, "args": tool_args, "type": "skill"})
        
        try:
            await self._log("info", f"🧩 执行 Skill: {skill_name}", None, tool_name)
            skill_result = await execute_skill(skill, tool_args, log_callback=self.log_callback)
            
            # 转换为 ToolResult
            result = ToolResult(
                success=skill_result.success,
                output=skill_result.output,
                error=skill_result.error
            )
            
            if result.success:
                await self._log(
                    "output",
                    f"📤 Skill {skill_name} 输出 ({len(result.output)} 字符)",
                    result.output[:2000] if result.output else "无输出",
                    tool_name
                )
            else:
                await self._log(
                    "error",
                    f"❌ Skill {skill_name} 执行失败",
                    result.error,
                    tool_name
                )
            
            # 分析输出
            await self._analyze_output(tool_name, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Skill execution error: {e}")
            result = ToolResult(success=False, output="", error=str(e))
            await self._log("error", f"❌ Skill {skill_name} 异常", str(e), tool_name)
            return result
    
    async def _execute_web_search(self, tool_args: dict) -> ToolResult:
        """执行联网搜索"""
        if not self.web_search:
            return ToolResult(success=False, output="", error="联网搜索未启用")
        
        query = tool_args.get('query', '')
        if not query:
            return ToolResult(success=False, output="", error="搜索关键词不能为空")
        
        self.tools_used.append({"name": "web_search", "args": tool_args, "type": "search"})
        
        try:
            await self._log("info", f"🔍 搜索: {query}", None, "web_search")
            results = await self.web_search.search(query)
            
            if not results:
                return ToolResult(success=True, output="未找到相关结果")
            
            # 格式化搜索结果
            output_lines = [f"找到 {len(results)} 条结果:\n"]
            for i, r in enumerate(results, 1):
                output_lines.append(f"{i}. {r.title}")
                output_lines.append(f"   URL: {r.url}")
                output_lines.append(f"   {r.snippet}\n")
            
            output = "\n".join(output_lines)
            
            await self._log(
                "output",
                f"📤 搜索结果 ({len(results)} 条)",
                output[:2000],
                "web_search"
            )
            
            return ToolResult(success=True, output=output)
            
        except Exception as e:
            logger.error(f"Web search error: {e}")
            return ToolResult(success=False, output="", error=str(e))
    
    async def _execute_ask_user(self, tool_args: dict) -> ToolResult:
        """执行 ask_user 工具，暂停等待用户回复"""
        question = tool_args.get('question', '')
        context = tool_args.get('context', '')
        options = tool_args.get('options', [])
        
        if not question:
            return ToolResult(success=False, output="", error="问题不能为空")
        
        self.tools_used.append({"name": "ask_user", "args": tool_args, "type": "interaction"})
        
        # 构造问题显示
        question_display = question
        if context:
            question_display = f"{context}\n\n{question}"
        if options:
            question_display += "\n\n可选项:\n" + "\n".join([f"  • {opt}" for opt in options])
        
        await self._log("info", "❓ AI 向用户提问", question_display, "ask_user")
        
        # 抛出暂停异常，让 run() 方法处理
        raise AgentPauseException(
            question=question,
            context=context,
            options=options,
            agent_state=self._get_state()
        )

    async def _analyze_output(self, tool_name: str, result: ToolResult):
        """分析工具输出，提取发现"""
        if not result.success or not result.output:
            return
        
        output = result.output.lower()
        
        # 简单的关键词检测
        findings_keywords = {
            "critical": ["rce", "remote code execution", "command injection", "sql injection"],
            "high": ["xss", "cross-site scripting", "authentication bypass", "sensitive data"],
            "medium": ["information disclosure", "directory listing", "version disclosure"],
            "low": ["missing header", "cookie without", "http only"],
        }
        
        for severity, keywords in findings_keywords.items():
            for keyword in keywords:
                if keyword in output:
                    finding = {
                        "tool": tool_name,
                        "severity": severity,
                        "keyword": keyword,
                        "snippet": output[:500]
                    }
                    self.findings.append(finding)
                    await self._log(
                        "success" if severity in ["critical", "high"] else "info",
                        f"🎯 发现: {keyword} ({severity})",
                        f"工具: {tool_name}",
                        tool_name
                    )
                    break


async def run_security_agent(
    target: str,
    scan_context: dict,
    log_callback: Callable = None,
    max_iterations: int = 0,
    custom_prompt: str = None,
    restored_state: dict = None,
    user_reply: str = None,
    session_factory = None,
    llm_config: dict = None,
    search_config: dict = None
) -> dict:
    """运行安全测试 Agent
    
    Args:
        target: 目标
        scan_context: 初始扫描上下文
        log_callback: 日志回调
        max_iterations: 最大迭代次数，0 表示无限制
        custom_prompt: 用户自定义提示词
        restored_state: 从暂停恢复时的 agent 状态
        user_reply: 用户回复（从暂停恢复时传入）
        session_factory: 数据库会话工厂 (Celery 任务中必须传入以避免事件循环冲突)
        llm_config: LLM 配置 (预加载，避免 Agent 内部访问数据库)
        search_config: 搜索配置 (预加载，避免 Agent 内部访问数据库)
        
    Returns:
        Agent 执行结果，如果暂停会包含 paused=True 和 agent_state
    """
    agent = SecurityAgent(
        target=target,
        scan_context=scan_context,
        log_callback=log_callback,
        max_iterations=max_iterations,
        custom_prompt=custom_prompt,
        restored_state=restored_state,
        session_factory=session_factory,
        llm_config=llm_config,
        search_config=search_config
    )
    return await agent.run(user_reply=user_reply)
