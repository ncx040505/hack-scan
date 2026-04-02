"""LLM integration for vulnerability analysis"""
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from pydantic import BaseModel, Field
from loguru import logger

from app.core.config import get_settings

settings = get_settings()


class VulnAnalysisResult(BaseModel):
    """LLM 漏洞分析结果结构"""
    summary: str = Field(description="漏洞概述")
    severity_assessment: str = Field(description="严重性评估")
    exploitation_difficulty: str = Field(description="利用难度")
    business_impact: str = Field(description="业务影响")
    remediation_steps: list[str] = Field(description="修复步骤")
    false_positive_likelihood: int = Field(description="误报可能性 0-100")


class ScanSummaryResult(BaseModel):
    """扫描结果总结"""
    executive_summary: str = Field(description="执行摘要")
    risk_score: int = Field(description="风险评分 0-100")
    critical_findings: list[str] = Field(description="关键发现")
    attack_surface_analysis: str = Field(description="攻击面分析")
    priority_recommendations: list[str] = Field(description="优先修复建议")


class VulnAnalyzer:
    """LLM 驱动的漏洞分析器"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model=settings.llm_model,
            temperature=settings.llm_temperature,
            api_key=settings.openai_api_key or None,
            base_url=settings.openai_base_url,
        )
    
    async def analyze_vulnerability(
        self,
        vuln_name: str,
        vuln_type: str,
        evidence: str,
        context: str = ""
    ) -> VulnAnalysisResult:
        """分析单个漏洞"""
        parser = PydanticOutputParser(pydantic_object=VulnAnalysisResult)
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一名资深的安全研究员和渗透测试专家。
请基于提供的漏洞信息进行深度分析。
注意：
1. 客观评估漏洞的真实风险
2. 考虑误报的可能性
3. 提供可操作的修复建议

{format_instructions}"""),
            ("human", """请分析以下漏洞:

漏洞名称: {vuln_name}
漏洞类型: {vuln_type}
证据/Payload: 
```
{evidence}
```
上下文信息: {context}
""")
        ])
        
        chain = prompt | self.llm | parser
        
        try:
            result = await chain.ainvoke({
                "vuln_name": vuln_name,
                "vuln_type": vuln_type,
                "evidence": evidence,
                "context": context,
                "format_instructions": parser.get_format_instructions()
            })
            return result
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            raise
    
    async def summarize_scan(
        self,
        target: str,
        vulnerabilities: list[dict],
        scan_info: dict
    ) -> ScanSummaryResult:
        """生成扫描结果总结"""
        parser = PydanticOutputParser(pydantic_object=ScanSummaryResult)
        
        # 构建漏洞摘要
        vuln_summary = "\n".join([
            f"- [{v.get('severity', 'UNKNOWN')}] {v.get('name', 'Unknown')}: {v.get('location', 'N/A')}"
            for v in vulnerabilities[:50]  # 限制数量避免 token 过多
        ])
        
        prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一名安全顾问，正在为客户生成漏洞扫描报告摘要。
请提供：
1. 面向管理层的执行摘要（简洁明了）
2. 基于发现的漏洞给出风险评分
3. 突出最关键的安全问题
4. 优先级排序的修复建议

{format_instructions}"""),
            ("human", """扫描目标: {target}

扫描信息:
- 扫描类型: {scan_type}
- 扫描时长: {duration}
- 发现漏洞总数: {vuln_count}

发现的漏洞:
{vuln_summary}

请生成分析报告。
""")
        ])
        
        chain = prompt | self.llm | parser
        
        try:
            result = await chain.ainvoke({
                "target": target,
                "scan_type": scan_info.get("scan_type", "unknown"),
                "duration": scan_info.get("duration", "N/A"),
                "vuln_count": len(vulnerabilities),
                "vuln_summary": vuln_summary or "未发现漏洞",
                "format_instructions": parser.get_format_instructions()
            })
            return result
        except Exception as e:
            logger.error(f"LLM summarization failed: {e}")
            raise
    
    async def filter_false_positives(
        self,
        vulnerabilities: list[dict]
    ) -> list[dict]:
        """使用 LLM 过滤误报"""
        prompt = ChatPromptTemplate.from_messages([
            ("system", """你是一名漏洞分析专家。
请判断以下漏洞报告是否为误报（false positive）。
考虑因素：
1. 证据是否充分
2. 漏洞特征是否明确
3. 上下文是否合理

对每个漏洞返回 JSON 格式：
{{"id": "漏洞ID", "is_false_positive": true/false, "confidence": 0-100, "reason": "判断理由"}}
"""),
            ("human", "漏洞列表：\n{vulns}")
        ])
        
        # 批量处理，每次最多 10 个
        results = []
        for i in range(0, len(vulnerabilities), 10):
            batch = vulnerabilities[i:i+10]
            # ... 处理逻辑
        
        return results


# 单例实例
_analyzer: VulnAnalyzer | None = None


def get_analyzer() -> VulnAnalyzer:
    global _analyzer
    if _analyzer is None:
        _analyzer = VulnAnalyzer()
    return _analyzer
