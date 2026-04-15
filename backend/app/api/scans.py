"""Scan API endpoints"""
import uuid
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from loguru import logger

from app.core.database import get_db, get_mongo_db, get_redis
from app.core.scan_logger import get_scan_logger
from app.core.vulnerability_fingerprint import severity_rank, vulnerability_fingerprint
from app.models.database import ScanTask, Vulnerability, ScanStatus, SeverityLevel, ScanMessage, ScanChatMessage
from app.schemas.scan import (
    ScanTaskCreate, ScanTaskResponse, ScanTaskList,
    VulnerabilityResponse, VulnerabilityList, ScanProgressResponse,
    ScanLogsResponse, ScanLogEntry
)
from tasks.scan_tasks import execute_scan
from tasks.celery_app import celery_app

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post("", response_model=ScanTaskResponse)
async def create_scan(
    scan_req: ScanTaskCreate,
    db: AsyncSession = Depends(get_db)
):
    """创建新的扫描任务"""
    task_id = str(uuid.uuid4())
    
    # 创建数据库记录
    scan_task = ScanTask(
        id=task_id,
        target=scan_req.target,
        scan_type=scan_req.scan_type,
        status=ScanStatus.PENDING,
        config=scan_req.config.model_dump(),
        remark=scan_req.remark,
    )
    
    db.add(scan_task)
    await db.commit()
    await db.refresh(scan_task)
    
    # 提交 Celery 任务
    execute_scan.delay(
        scan_task_id=task_id,
        target=scan_req.target,
        scan_type=scan_req.scan_type,
        config=scan_req.config.model_dump()
    )
    
    logger.info(f"Scan task created: {task_id} for {scan_req.target}")
    
    return ScanTaskResponse(
        id=scan_task.id,
        target=scan_task.target,
        scan_type=scan_task.scan_type,
        status=scan_task.status,
        config=scan_task.config,
        started_at=scan_task.started_at,
        completed_at=scan_task.completed_at,
        created_at=scan_task.created_at,
        llm_summary=scan_task.llm_summary,
        llm_risk_score=scan_task.llm_risk_score,
        vulnerability_count=0,
        remark=scan_task.remark
    )


@router.get("", response_model=ScanTaskList)
async def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    status: ScanStatus | None = None,
    db: AsyncSession = Depends(get_db)
):
    """获取扫描任务列表"""
    query = select(ScanTask).order_by(ScanTask.created_at.desc())
    
    if status:
        query = query.where(ScanTask.status == status)
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    tasks = result.scalars().all()
    
    # 获取总数
    count_query = select(func.count(ScanTask.id))
    if status:
        count_query = count_query.where(ScanTask.status == status)
    total = (await db.execute(count_query)).scalar()
    
    # 获取漏洞数量
    items = []
    for task in tasks:
        vuln_count_query = select(func.count(Vulnerability.id)).where(
            Vulnerability.scan_task_id == task.id
        )
        vuln_count = (await db.execute(vuln_count_query)).scalar()
        
        items.append(ScanTaskResponse(
            id=task.id,
            target=task.target,
            scan_type=task.scan_type,
            status=task.status,
            config=task.config,
            started_at=task.started_at,
            completed_at=task.completed_at,
            created_at=task.created_at,
            llm_summary=task.llm_summary,
            llm_risk_score=task.llm_risk_score,
            vulnerability_count=vuln_count,
            remark=task.remark
        ))
    
    return ScanTaskList(total=total, items=items)


@router.get("/{scan_id}", response_model=ScanTaskResponse)
async def get_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """获取扫描任务详情"""
    result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    # 获取漏洞数量
    vuln_count_query = select(func.count(Vulnerability.id)).where(
        Vulnerability.scan_task_id == task.id
    )
    vuln_count = (await db.execute(vuln_count_query)).scalar()
    
    return ScanTaskResponse(
        id=task.id,
        target=task.target,
        scan_type=task.scan_type,
        status=task.status,
        config=task.config,
        started_at=task.started_at,
        completed_at=task.completed_at,
        created_at=task.created_at,
        llm_summary=task.llm_summary,
        llm_risk_score=task.llm_risk_score,
        vulnerability_count=vuln_count,
        remark=task.remark
    )


@router.get("/{scan_id}/progress", response_model=ScanProgressResponse)
async def get_scan_progress(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """获取扫描任务进度（从 Celery 任务状态）"""
    result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    phase = None
    message = None
    
    # 从 Celery 获取任务状态
    if task.status == ScanStatus.RUNNING:
        # 查找关联的 Celery task
        async_result = celery_app.AsyncResult(f"scan-{scan_id}")
        if async_result.state == "RUNNING":
            meta = async_result.info or {}
            phase = meta.get("phase", "running")
            
            phase_messages = {
                "initializing": "初始化扫描器...",
                "running_nmap": "正在进行端口扫描 (Nmap)...",
                "running_nuclei": "正在进行漏洞扫描 (Nuclei)...",
                "llm_analysis": "AI 正在分析扫描结果...",
            }
            message = phase_messages.get(phase, f"执行中: {phase}")
    elif task.status == ScanStatus.PENDING:
        phase = "queued"
        message = "等待执行..."
    elif task.status == ScanStatus.COMPLETED:
        phase = "completed"
        message = "扫描完成"
    elif task.status == ScanStatus.FAILED:
        phase = "failed"
        message = "扫描失败"
    
    return ScanProgressResponse(
        scan_id=scan_id,
        status=task.status,
        phase=phase,
        message=message
    )


@router.get("/{scan_id}/logs", response_model=ScanLogsResponse)
async def get_scan_logs(
    scan_id: str,
    since_index: int = Query(0, ge=0, description="获取此索引之后的日志"),
    db: AsyncSession = Depends(get_db)
):
    """获取扫描任务的实时日志"""
    # 验证任务存在
    result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    # 从 Redis 获取日志
    scan_logger = get_scan_logger(scan_id)
    try:
        logs, next_index = scan_logger.get_logs(since_index)
    finally:
        scan_logger.close()
    
    return ScanLogsResponse(
        scan_id=scan_id,
        logs=[ScanLogEntry(**log) for log in logs],
        next_index=next_index
    )


@router.get("/{scan_id}/vulnerabilities", response_model=VulnerabilityList)
async def get_scan_vulnerabilities(
    scan_id: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    severity: SeverityLevel | None = None,
    db: AsyncSession = Depends(get_db)
):
    """获取扫描任务的漏洞列表"""
    # 验证任务存在
    task_result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    if not task_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    query = select(Vulnerability).where(
        Vulnerability.scan_task_id == scan_id
    ).order_by(Vulnerability.severity, Vulnerability.created_at.desc())
    
    if severity:
        query = query.where(Vulnerability.severity == severity)
    
    result = await db.execute(query)
    vulns = result.scalars().all()

    def is_better(candidate: Vulnerability, existing: Vulnerability) -> bool:
        if candidate.llm_remediation and not existing.llm_remediation:
            return True
        if candidate.llm_analysis and not existing.llm_analysis:
            return True
        candidate_rank = severity_rank(candidate.severity)
        existing_rank = severity_rank(existing.severity)
        if candidate_rank != existing_rank:
            return candidate_rank > existing_rank
        if candidate.created_at and existing.created_at:
            return candidate.created_at > existing.created_at
        return False

    deduped: dict[str, Vulnerability] = {}
    for vuln in vulns:
        key = vulnerability_fingerprint(vuln.name, vuln.category, vuln.location)
        if not key:
            key = vuln.id
        existing = deduped.get(key)
        if not existing or is_better(vuln, existing):
            deduped[key] = vuln

    deduped_list = list(deduped.values())
    total = len(deduped_list)
    items = deduped_list[skip: skip + limit]
    
    return VulnerabilityList(
        total=total,
        items=[VulnerabilityResponse.model_validate(v) for v in items]
    )


@router.get("/{scan_id}/attack-path")
async def get_attack_path(
    scan_id: str,
    refresh: bool = Query(False, description="强制重新生成攻击路径分析"),
    db: AsyncSession = Depends(get_db)
):
    """获取扫描任务的攻击路径分析"""
    from llm.analyzer import get_analyzer
    
    # 获取扫描任务
    result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    # 如果已有缓存且不需要刷新，直接返回
    if task.attack_path_analysis and not refresh:
        return {
            "success": True,
            "cached": True,
            "data": task.attack_path_analysis
        }
    
    # 获取漏洞列表
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_task_id == scan_id)
    )
    vulns = vuln_result.scalars().all()
    
    if not vulns:
        return {
            "success": True,
            "cached": False,
            "data": {
                "phases": [],
                "attack_chains": [],
                "risk_assessment": {
                    "overall_risk": "low",
                    "risk_score": 0,
                    "summary": "未发现漏洞",
                    "critical_paths": [],
                    "recommendations": ["继续保持良好的安全实践"]
                }
            }
        }
    
    # 分离端口信息和漏洞信息
    open_ports = []
    vulnerabilities = []
    
    for v in vulns:
        vuln_dict = {
            "id": v.id,
            "name": v.name,
            "severity": v.severity.value if hasattr(v.severity, 'value') else str(v.severity),
            "category": v.category,
            "description": v.description,
            "location": v.location,
            "evidence": v.evidence,
            "llm_analysis": v.llm_analysis,
        }
        
        if v.name.startswith("Open port:"):
            open_ports.append(vuln_dict)
        else:
            vulnerabilities.append(vuln_dict)
    
    # 调用 LLM 分析
    try:
        analyzer = get_analyzer()
        analysis_result = await analyzer.analyze_attack_path(
            target=task.target,
            vulnerabilities=vulnerabilities,
            open_ports=open_ports
        )
        
        # 转换为字典
        result_dict = analysis_result.model_dump()
        
        # 保存到数据库
        task.attack_path_analysis = result_dict
        await db.commit()
        
        return {
            "success": True,
            "cached": False,
            "data": result_dict
        }
        
    except Exception as e:
        logger.error(f"Attack path analysis failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"攻击路径分析失败: {str(e)}"
        )


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """取消扫描任务"""
    result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    if task.status not in (ScanStatus.PENDING, ScanStatus.RUNNING, ScanStatus.PAUSED):
        raise HTTPException(
            status_code=400,
            detail=f"Cannot cancel task in {task.status} status"
        )
    
    task.status = ScanStatus.CANCELLED
    task.completed_at = datetime.utcnow()
    await db.commit()
    
    # 尝试取消 Celery 任务
    try:
        celery_app.control.revoke(f"scan-{scan_id}", terminate=True)
    except Exception as e:
        logger.warning(f"Failed to revoke celery task: {e}")
    
    # 记录取消日志
    scan_logger = get_scan_logger(scan_id)
    try:
        scan_logger.log("info", "⛔ 扫描任务已被用户取消")
    finally:
        scan_logger.close()
    
    return {"message": "扫描已取消", "scan_id": scan_id}


@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """删除扫描任务"""
    result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    if task.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(
            status_code=400,
            detail="Cannot delete running task. Cancel it first."
        )
    
    # 删除关联的漏洞
    await db.execute(
        Vulnerability.__table__.delete().where(Vulnerability.scan_task_id == scan_id)
    )
    
    # 删除关联的对话消息
    await db.execute(
        ScanMessage.__table__.delete().where(ScanMessage.scan_task_id == scan_id)
    )
    await db.execute(
        ScanChatMessage.__table__.delete().where(ScanChatMessage.scan_task_id == scan_id)
    )
    
    # 删除扫描任务
    await db.delete(task)
    await db.commit()
    
    # 清理 Redis 日志
    scan_logger = get_scan_logger(scan_id)
    try:
        scan_logger.clear()
    finally:
        scan_logger.close()
    
    logger.info(f"Scan task deleted: {scan_id}")
    
    return {"message": "扫描已删除", "scan_id": scan_id}


@router.post("/batch-delete")
async def batch_delete_scans(
    scan_ids: list[str] = Body(..., embed=True),
    db: AsyncSession = Depends(get_db)
):
    """批量删除扫描任务"""
    if not scan_ids:
        raise HTTPException(status_code=400, detail="未提供扫描任务ID")
    
    deleted_count = 0
    failed_count = 0
    failed_ids = []
    
    for scan_id in scan_ids:
        try:
            result = await db.execute(
                select(ScanTask).where(ScanTask.id == scan_id)
            )
            task = result.scalar_one_or_none()
            
            if not task:
                failed_count += 1
                failed_ids.append({"id": scan_id, "reason": "任务不存在"})
                continue
            
            if task.status in (ScanStatus.PENDING, ScanStatus.RUNNING):
                failed_count += 1
                failed_ids.append({"id": scan_id, "reason": "任务正在运行，请先取消"})
                continue
            
            # 删除关联的漏洞
            await db.execute(
                Vulnerability.__table__.delete().where(Vulnerability.scan_task_id == scan_id)
            )
            
            # 删除关联的对话消息
            await db.execute(
                ScanMessage.__table__.delete().where(ScanMessage.scan_task_id == scan_id)
            )
            await db.execute(
                ScanChatMessage.__table__.delete().where(ScanChatMessage.scan_task_id == scan_id)
            )
            
            # 删除扫描任务
            await db.delete(task)
            
            # 清理 Redis 日志
            scan_logger = get_scan_logger(scan_id)
            try:
                scan_logger.clear()
            finally:
                scan_logger.close()
            
            deleted_count += 1
            logger.info(f"Scan task deleted in batch: {scan_id}")
            
        except Exception as e:
            failed_count += 1
            failed_ids.append({"id": scan_id, "reason": str(e)})
            logger.error(f"Failed to delete scan {scan_id}: {e}")
    
    await db.commit()
    
    return {
        "message": f"成功删除 {deleted_count} 个任务",
        "deleted_count": deleted_count,
        "failed_count": failed_count,
        "failed_ids": failed_ids
    }


# ============ Scan Messages API ============

from app.models.database import ScanMessage, MessageRole
from app.schemas.scan import ScanMessageCreate, ScanMessageResponse, ScanMessageList
from tasks.scan_tasks import resume_scan


@router.get("/{scan_id}/messages", response_model=ScanMessageList)
async def get_scan_messages(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """获取扫描任务的对话消息"""
    # 验证任务存在
    result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    # 获取消息列表
    result = await db.execute(
        select(ScanMessage)
        .where(ScanMessage.scan_task_id == scan_id)
        .order_by(ScanMessage.created_at.asc())
    )
    messages = result.scalars().all()
    
    # 获取最新的 agent 问题（如果扫描处于暂停状态）
    pending_question = None
    if task.status == ScanStatus.PAUSED:
        agent_msgs = [m for m in messages if m.role == MessageRole.AGENT and not m.is_processed]
        if agent_msgs:
            pending_question = agent_msgs[-1].content
    
    return ScanMessageList(
        scan_id=scan_id,
        messages=[
            ScanMessageResponse(
                id=m.id,
                scan_task_id=m.scan_task_id,
                role=m.role.value,
                content=m.content,
                is_processed=m.is_processed,
                created_at=m.created_at,
            )
            for m in messages
        ],
        is_paused=task.status == ScanStatus.PAUSED,
        pending_question=pending_question
    )


@router.post("/{scan_id}/messages", response_model=ScanMessageResponse)
async def send_scan_message(
    scan_id: str,
    message: ScanMessageCreate,
    db: AsyncSession = Depends(get_db)
):
    """发送用户消息并恢复扫描"""
    # 验证任务存在且处于暂停状态
    result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    if task.status != ScanStatus.PAUSED:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot send message to task in {task.status.value} status. Task must be paused."
        )
    
    # 创建用户消息
    msg = ScanMessage(
        id=str(uuid.uuid4()),
        scan_task_id=scan_id,
        role=MessageRole.USER,
        content=message.content,
        is_processed=False,
    )
    db.add(msg)
    await db.commit()
    await db.refresh(msg)
    
    # 记录日志
    scan_logger = get_scan_logger(scan_id)
    try:
        scan_logger.info("💬 用户回复", message.content[:200])
    finally:
        scan_logger.close()
    
    # 触发恢复扫描任务
    resume_scan.delay(scan_task_id=scan_id)
    
    logger.info(f"User message sent for scan {scan_id}, resuming scan")
    
    return ScanMessageResponse(
        id=msg.id,
        scan_task_id=msg.scan_task_id,
        role=msg.role.value,
        content=msg.content,
        is_processed=msg.is_processed,
        created_at=msg.created_at,
    )


# ============ Post-Scan Chat API ============

from app.models.database import ScanChatMessage, ChatRole
from app.schemas.scan import ChatRequest, ChatResponse, ChatHistory
from llm.analyzer import get_analyzer


@router.get("/{scan_id}/chat", response_model=ChatHistory)
async def get_chat_history(
    scan_id: str,
    db: AsyncSession = Depends(get_db)
):
    """获取扫描完成后的对话历史"""
    # 验证任务存在
    result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    # 获取对话历史
    result = await db.execute(
        select(ScanChatMessage)
        .where(ScanChatMessage.scan_task_id == scan_id)
        .order_by(ScanChatMessage.created_at.asc())
    )
    messages = result.scalars().all()
    
    # 只有完成/失败/取消的扫描才能继续对话
    can_chat = task.status in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]
    
    return ChatHistory(
        scan_id=scan_id,
        messages=[
            ChatResponse(
                id=m.id,
                scan_id=m.scan_task_id,
                role=m.role.value,
                content=m.content,
                created_at=m.created_at,
            )
            for m in messages
        ],
        can_chat=can_chat
    )


@router.post("/{scan_id}/chat", response_model=ChatResponse)
async def chat_about_scan(
    scan_id: str,
    request: ChatRequest,
    db: AsyncSession = Depends(get_db)
):
    """对扫描结果进行对话分析"""
    # 验证任务存在
    result = await db.execute(
        select(ScanTask).where(ScanTask.id == scan_id)
    )
    task = result.scalar_one_or_none()
    
    if not task:
        raise HTTPException(status_code=404, detail="Scan task not found")
    
    # 只有完成/失败/取消的扫描才能继续对话
    if task.status not in [ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED]:
        raise HTTPException(
            status_code=400,
            detail=f"Cannot chat about scan in {task.status.value} status. Scan must be completed, failed, or cancelled."
        )
    
    # 保存用户消息
    user_msg = ScanChatMessage(
        id=str(uuid.uuid4()),
        scan_task_id=scan_id,
        role=ChatRole.USER,
        content=request.message,
    )
    db.add(user_msg)
    await db.flush()
    
    # 获取扫描上下文
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.scan_task_id == scan_id)
    )
    vulns = result.scalars().all()
    
    # 构建漏洞摘要
    vuln_summary = []
    for v in vulns[:30]:  # 限制数量
        vuln_summary.append(f"- [{v.severity.value.upper()}] {v.name}: {v.location or 'N/A'}")
        if v.llm_analysis:
            vuln_summary.append(f"  AI分析: {v.llm_analysis[:200]}")
    
    # 获取历史对话
    result = await db.execute(
        select(ScanChatMessage)
        .where(ScanChatMessage.scan_task_id == scan_id)
        .order_by(ScanChatMessage.created_at.asc())
    )
    history = result.scalars().all()
    
    # 构建对话历史字符串
    chat_history = []
    for msg in history[-10:]:  # 限制最近10条
        role = "用户" if msg.role == ChatRole.USER else "助手"
        chat_history.append(f"{role}: {msg.content}")
    
    # 获取活跃的 LLM 配置
    from app.api.settings import get_active_llm_config
    db_config = await get_active_llm_config(db)
    
    if not db_config:
        raise HTTPException(status_code=503, detail="LLM 配置未设置，请在设置中配置 LLM")
    
    # 调用 LLM 回答问题
    from langchain_openai import ChatOpenAI
    from langchain_core.prompts import ChatPromptTemplate
    
    llm = ChatOpenAI(
        model=db_config.model,
        temperature=0.7,
        api_key=db_config.api_key,
        base_url=db_config.api_base_url,
        max_tokens=db_config.max_tokens,
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", """你是一名专业的安全分析师，正在帮助用户分析扫描结果。

扫描目标: {target}
扫描类型: {scan_type}
扫描状态: {status}
AI 总结: {llm_summary}
风险评分: {risk_score}/100

发现的漏洞:
{vuln_summary}

历史对话:
{chat_history}

请根据以上信息回答用户的问题。注意：
1. 提供专业、准确的安全分析
2. 如果用户询问具体漏洞，提供详细的技术解释
3. 给出可操作的修复建议
4. 用中文回答"""),
        ("human", "{question}")
    ])
    
    chain = prompt | llm
    
    try:
        response = await chain.ainvoke({
            "target": task.target,
            "scan_type": task.scan_type,
            "status": task.status.value,
            "llm_summary": task.llm_summary or "暂无",
            "risk_score": task.llm_risk_score or "未评估",
            "vuln_summary": "\n".join(vuln_summary) or "未发现漏洞",
            "chat_history": "\n".join(chat_history) if chat_history else "无历史对话",
            "question": request.message
        })
        
        assistant_content = response.content
    except Exception as e:
        logger.error(f"Chat LLM failed: {e}")
        assistant_content = f"抱歉，分析过程中出现错误: {str(e)}"
    
    # 保存 AI 回复
    assistant_msg = ScanChatMessage(
        id=str(uuid.uuid4()),
        scan_task_id=scan_id,
        role=ChatRole.ASSISTANT,
        content=assistant_content,
    )
    db.add(assistant_msg)
    await db.commit()
    await db.refresh(assistant_msg)
    
    logger.info(f"Chat response generated for scan {scan_id}")
    
    return ChatResponse(
        id=assistant_msg.id,
        scan_id=assistant_msg.scan_task_id,
        role=assistant_msg.role.value,
        content=assistant_msg.content,
        created_at=assistant_msg.created_at,
    )
