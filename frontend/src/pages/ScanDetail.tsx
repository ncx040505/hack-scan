import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import { AlertTriangle, Clock, CheckCircle, Brain, Loader2, ChevronDown, ChevronUp, Terminal, Bot, Wrench, AlertCircle, CheckCircle2, Info, XCircle, Trash2, MessageCircle, Send, Pause, MessageSquare, Server, Eye, EyeOff, Shield } from 'lucide-react'
import { getScan, getVulnerabilities, getScanProgress, getScanLogs, cancelScan, deleteScan, getScanMessages, sendScanMessage, getScanChatHistory, sendScanChatMessage, Vulnerability, ScanLogEntry } from '../lib/api'
import SeverityBadge from '../components/SeverityBadge'
import { useState, useEffect, useRef } from 'react'

const statusLabels: Record<string, string> = {
  PENDING: '等待中',
  RUNNING: '扫描中',
  PAUSED: '等待回复',
  COMPLETED: '已完成',
  FAILED: '失败',
  CANCELLED: '已取消',
}

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [showLogs, setShowLogs] = useState(true)
  const [showVulns, setShowVulns] = useState(false) // 默认隐藏，扫描完成后自动展开
  const [logs, setLogs] = useState<ScanLogEntry[]>([])
  const [logIndex, setLogIndex] = useState(0)
  const logsEndRef = useRef<HTMLDivElement>(null)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)

  const { data: scan, isLoading: scanLoading } = useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => getScan(scanId!),
    enabled: !!scanId,
    refetchInterval: (query) => {
      const data = query.state.data
      return data?.status === 'RUNNING' || data?.status === 'PENDING' || data?.status === 'PAUSED' ? 2000 : false
    },
  })

  // 扫描完成后自动展开漏洞列表
  useEffect(() => {
    if (scan?.status === 'COMPLETED' || scan?.status === 'FAILED' || scan?.status === 'CANCELLED') {
      setShowVulns(true)
    }
  }, [scan?.status])

  const { data: progress } = useQuery({
    queryKey: ['scan-progress', scanId],
    queryFn: () => getScanProgress(scanId!),
    enabled: !!scanId && (scan?.status === 'RUNNING' || scan?.status === 'PENDING'),
    refetchInterval: 1500,
  })

  // Fetch logs incrementally
  const { data: logsData } = useQuery({
    queryKey: ['scan-logs', scanId, logIndex],
    queryFn: () => getScanLogs(scanId!, logIndex),
    enabled: !!scanId,
    refetchInterval: (query) => {
      // Keep polling for logs while scan is running or just completed
      return scan?.status === 'RUNNING' || scan?.status === 'PENDING' ? 1000 : false
    },
  })

  // Append new logs when received
  useEffect(() => {
    if (logsData && logsData.logs.length > 0) {
      setLogs(prev => [...prev, ...logsData.logs])
      setLogIndex(logsData.next_index)
    }
  }, [logsData])

  // Auto-scroll to bottom
  useEffect(() => {
    if (showLogs && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, showLogs])

  // Reset logs when scan changes
  useEffect(() => {
    setLogs([])
    setLogIndex(0)
  }, [scanId])

  const { data: vulns, isLoading: vulnsLoading } = useQuery({
    queryKey: ['vulnerabilities', scanId],
    queryFn: () => getVulnerabilities(scanId!),
    enabled: !!scanId && scan?.status === 'COMPLETED',
  })

  const cancelMutation = useMutation({
    mutationFn: () => cancelScan(scanId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })

  const deleteMutation = useMutation({
    mutationFn: () => deleteScan(scanId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
      navigate('/')
    },
  })

  if (scanLoading) {
    return <div className="text-center py-12">加载中...</div>
  }

  if (!scan) {
    return <div className="text-center py-12 text-red-500">扫描任务未找到</div>
  }

  const isActive = scan.status === 'RUNNING' || scan.status === 'PENDING' || scan.status === 'PAUSED'
  const canDelete = scan.status === 'COMPLETED' || scan.status === 'CANCELLED' || scan.status === 'FAILED'

  return (
    <div>
      {/* Header */}
      <div className="mb-6 flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold mb-2">{scan.target}</h1>
          <div className="flex items-center gap-4 text-gray-500 dark:text-gray-400">
            <span className="capitalize">{scan.scan_type} 扫描</span>
            <span>•</span>
            <span>{format(new Date(scan.created_at), 'yyyy-MM-dd HH:mm')}</span>
            <span>•</span>
            <StatusBadge status={scan.status} />
          </div>
        </div>
        
        {/* Action Buttons */}
        <div className="flex gap-2">
          {isActive && (
            <button
              onClick={() => cancelMutation.mutate()}
              disabled={cancelMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg disabled:opacity-50"
            >
              <XCircle className="w-4 h-4" />
              {cancelMutation.isPending ? '取消中...' : '取消扫描'}
            </button>
          )}
          
          {canDelete && (
            <button
              onClick={() => setShowDeleteConfirm(true)}
              className="flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg"
            >
              <Trash2 className="w-4 h-4" />
              删除
            </button>
          )}
        </div>
      </div>

      {/* Delete Confirmation Modal */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4 shadow-xl">
            <h3 className="text-lg font-semibold mb-2">确认删除</h3>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              确定要删除此扫描任务吗？此操作不可恢复，所有相关漏洞数据也将被删除。
            </p>
            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowDeleteConfirm(false)}
                className="px-4 py-2 bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600 rounded-lg"
              >
                取消
              </button>
              <button
                onClick={() => {
                  deleteMutation.mutate()
                  setShowDeleteConfirm(false)
                }}
                disabled={deleteMutation.isPending}
                className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg disabled:opacity-50"
              >
                {deleteMutation.isPending ? '删除中...' : '确认删除'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Progress (for running/pending scans) */}
      {isActive && scan.status !== 'PAUSED' && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 mb-6 shadow">
          <div className="flex items-center gap-3">
            <Loader2 className="w-6 h-6 text-blue-500 animate-spin" />
            <div>
              <h2 className="font-semibold text-blue-600 dark:text-blue-400">
                {scan.status === 'PENDING' ? '等待执行' : '扫描进行中'}
              </h2>
              <p className="text-gray-500 dark:text-gray-400 text-sm">
                {progress?.message || '正在处理...'}
              </p>
            </div>
          </div>
          {progress?.phase && (
            <div className="mt-4">
              <div className="flex gap-2 text-sm">
                <ProgressStep 
                  label="初始化" 
                  active={progress.phase === 'initializing' || progress.phase === 'queued'} 
                  done={['running_nmap', 'running_nuclei', 'ai_agent', 'llm_analysis', 'COMPLETED'].includes(progress.phase || '')}
                />
                <ProgressStep 
                  label="端口扫描" 
                  active={progress.phase === 'running_nmap'} 
                  done={['running_nuclei', 'ai_agent', 'llm_analysis', 'COMPLETED'].includes(progress.phase || '')}
                />
                <ProgressStep 
                  label="漏洞扫描" 
                  active={progress.phase === 'running_nuclei'} 
                  done={['ai_agent', 'llm_analysis', 'COMPLETED'].includes(progress.phase || '')}
                />
                <ProgressStep 
                  label="AI 测试" 
                  active={progress.phase === 'ai_agent'} 
                  done={['llm_analysis', 'COMPLETED'].includes(progress.phase || '')}
                />
                <ProgressStep 
                  label="AI 分析" 
                  active={progress.phase === 'llm_analysis'} 
                  done={progress.phase === 'COMPLETED'}
                />
              </div>
            </div>
          )}
        </div>
      )}
      
      {/* Paused - Agent asking user */}
      {scan.status === 'PAUSED' && (
        <AgentQuestionPanel scanId={scanId!} />
      )}

      {/* Real-time Logs */}
      {(isActive || logs.length > 0) && (
        <div className="bg-white dark:bg-gray-800 rounded-lg mb-6 overflow-hidden shadow">
          <button 
            onClick={() => setShowLogs(!showLogs)}
            className="w-full px-4 py-3 flex items-center justify-between border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
          >
            <div className="flex items-center gap-2">
              <Terminal className="w-5 h-5 text-green-500" />
              <h2 className="font-semibold">执行日志</h2>
              <span className="text-xs text-gray-500">({logs.length} 条)</span>
            </div>
            {showLogs ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
          
          {showLogs && (
            <div className={`${showVulns ? 'max-h-96' : 'max-h-[70vh]'} overflow-y-auto p-4 space-y-2 bg-gray-50 dark:bg-gray-900 font-mono text-sm transition-all duration-300`}>
              {logs.length === 0 ? (
                <div className="text-gray-500 text-center py-4">等待日志...</div>
              ) : (
                logs.map((log, idx) => (
                  <LogEntry key={idx} log={log} />
                ))
              )}
              <div ref={logsEndRef} />
            </div>
          )}
        </div>
      )}

      {/* LLM Summary */}
      {scan.llm_summary && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 mb-6 shadow">
          <div className="flex items-center gap-2 mb-3">
            <Brain className="w-5 h-5 text-purple-500" />
            <h2 className="font-semibold">AI 分析</h2>
            {scan.llm_risk_score !== null && (
              <span className="ml-auto">
                风险评分: <RiskScore score={scan.llm_risk_score} />
              </span>
            )}
          </div>
          <p className="text-gray-600 dark:text-gray-300 whitespace-pre-wrap">{scan.llm_summary}</p>
        </div>
      )}

      {/* Separate open ports from vulnerabilities */}
      {(() => {
        const openPorts = vulns?.items.filter(v => v.name.startsWith('Open port:')) || []
        const actualVulns = vulns?.items.filter(v => !v.name.startsWith('Open port:')) || []
        
        return (
          <>
            {/* Collapsible Vulnerability Section Header */}
            <div className="bg-white dark:bg-gray-800 rounded-lg shadow mb-6">
              <button
                onClick={() => setShowVulns(!showVulns)}
                className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Shield className="w-5 h-5 text-orange-500" />
                  <h2 className="font-semibold">扫描结果</h2>
                  <span className="text-xs text-gray-500">
                    ({openPorts.length} 端口, {actualVulns.length} 漏洞)
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  {showVulns ? (
                    <>
                      <span className="text-xs text-gray-500">点击隐藏</span>
                      <EyeOff className="w-4 h-4 text-gray-400" />
                    </>
                  ) : (
                    <>
                      <span className="text-xs text-gray-500">点击展开</span>
                      <Eye className="w-4 h-4 text-gray-400" />
                    </>
                  )}
                </div>
              </button>
            </div>

            {showVulns && (
              <>
                {/* Open Ports Section */}
                {openPorts.length > 0 && (
                  <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow mb-6">
                    <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center gap-2">
                      <Server className="w-5 h-5 text-blue-500" />
                      <h2 className="font-semibold">开放端口</h2>
                      <span className="text-sm text-gray-500">({openPorts.length})</span>
                    </div>
                    <div className="p-4">
                      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                        {openPorts.map(port => (
                          <PortCard key={port.id} port={port} />
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* Stats - only count actual vulnerabilities */}
                <div className="grid grid-cols-4 gap-4 mb-6">
                  <StatBox label="漏洞数" value={actualVulns.length} />
                  <StatBox
                    label="严重"
                    value={actualVulns.filter(v => v.severity === 'critical').length}
                    color="text-red-500"
                  />
                  <StatBox
                    label="高危"
                    value={actualVulns.filter(v => v.severity === 'high').length}
                    color="text-orange-500"
                  />
                  <StatBox
                    label="中危"
                    value={actualVulns.filter(v => v.severity === 'medium').length}
                    color="text-yellow-500"
                  />
                </div>

                {/* Vulnerabilities */}
                <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow">
                  <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700">
                    <h2 className="font-semibold">漏洞列表</h2>
                  </div>

                  {vulnsLoading ? (
                    <div className="p-8 text-center text-gray-500 dark:text-gray-400">加载漏洞数据...</div>
                  ) : actualVulns.length === 0 ? (
                    <div className="p-8 text-center text-gray-500 dark:text-gray-400">
                      <CheckCircle className="w-12 h-12 mx-auto mb-2 text-green-500" />
                      未发现漏洞
                    </div>
                  ) : (
                    <div className="divide-y divide-gray-200 dark:divide-gray-700">
                      {actualVulns.map(vuln => (
                        <VulnRow key={vuln.id} vuln={vuln} />
                      ))}
                    </div>
                  )}
                </div>
              </>
            )}
          </>
        )
      })()}
      
      {/* Post-Scan Chat - 扫描完成后的对话分析 */}
      {(scan.status === 'COMPLETED' || scan.status === 'FAILED' || scan.status === 'CANCELLED') && (
        <ScanChatPanel scanId={scanId!} />
      )}
    </div>
  )
}

function StatusBadge({ status }: { status: string }) {
  const colors: Record<string, string> = {
    PENDING: 'bg-yellow-500',
    RUNNING: 'bg-blue-500',
    PAUSED: 'bg-orange-500',
    COMPLETED: 'bg-green-500',
    FAILED: 'bg-red-500',
    CANCELLED: 'bg-gray-500',
  }

  return (
    <span className={`px-2 py-1 text-xs rounded text-white ${colors[status] || 'bg-gray-500'}`}>
      {statusLabels[status] || status}
    </span>
  )
}

function StatBox({ label, value, color = '' }: { label: string; value: number; color?: string }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 text-center shadow">
      <p className={`text-3xl font-bold ${color || 'text-gray-900 dark:text-white'}`}>{value}</p>
      <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
    </div>
  )
}

function RiskScore({ score }: { score: number }) {
  const color =
    score >= 80 ? 'text-red-500' :
    score >= 60 ? 'text-orange-500' :
    score >= 40 ? 'text-yellow-500' :
    'text-green-500'

  return <span className={`font-bold ${color}`}>{score}/100</span>
}

function PortCard({ port }: { port: Vulnerability }) {
  // Parse port info from name like "Open port: ssh" and location like "10.0.5.1:22/tcp"
  const serviceName = port.name.replace('Open port: ', '')
  const locationMatch = port.location?.match(/:(\d+)\/(\w+)/)
  const portNum = locationMatch ? locationMatch[1] : ''
  const protocol = locationMatch ? locationMatch[2].toUpperCase() : ''
  
  return (
    <div className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg border border-gray-200 dark:border-gray-600">
      <div className="flex items-center justify-between mb-1">
        <span className="font-mono font-bold text-blue-600 dark:text-blue-400">{portNum}</span>
        <span className="text-xs px-1.5 py-0.5 bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 rounded">
          {protocol}
        </span>
      </div>
      <div className="text-sm font-medium text-gray-700 dark:text-gray-300">{serviceName}</div>
      {port.description && (
        <div className="text-xs text-gray-500 dark:text-gray-400 mt-1 truncate" title={port.description}>
          {port.description}
        </div>
      )}
    </div>
  )
}

function VulnRow({ vuln }: { vuln: Vulnerability }) {
  return (
    <div className="p-4 hover:bg-gray-50 dark:hover:bg-gray-750">
      <div className="flex items-start gap-3">
        <SeverityBadge severity={vuln.severity} />
        <div className="flex-1">
          <h3 className="font-medium">{vuln.name}</h3>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{vuln.location}</p>
          {vuln.description && (
            <p className="text-sm text-gray-600 dark:text-gray-300 mt-2">{vuln.description}</p>
          )}
          {vuln.llm_analysis && (
            <div className="mt-3 p-3 bg-gray-100 dark:bg-gray-700 rounded text-sm">
              <div className="flex items-center gap-1 text-purple-600 dark:text-purple-400 mb-1">
                <Brain className="w-4 h-4" />
                AI 分析
              </div>
              <p className="text-gray-600 dark:text-gray-300">{vuln.llm_analysis}</p>
            </div>
          )}
          {vuln.llm_remediation && (
            <div className="mt-2 text-sm">
              <span className="text-green-600 dark:text-green-400">修复建议: </span>
              <span className="text-gray-600 dark:text-gray-300">{vuln.llm_remediation}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function ProgressStep({ label, active, done }: { label: string; active: boolean; done: boolean }) {
  return (
    <div className={`flex-1 text-center py-2 px-3 rounded ${
      done ? 'bg-green-100 dark:bg-green-900/50 text-green-600 dark:text-green-400' :
      active ? 'bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400' :
      'bg-gray-200 dark:bg-gray-700 text-gray-500'
    }`}>
      {done ? '✓ ' : active ? '● ' : '○ '}{label}
    </div>
  )
}

function LogEntry({ log }: { log: ScanLogEntry }) {
  const [expanded, setExpanded] = useState(false)
  
  const typeConfig: Record<string, { icon: React.ReactNode; color: string; bg: string }> = {
    info: { 
      icon: <Info className="w-4 h-4" />, 
      color: 'text-blue-600 dark:text-blue-400', 
      bg: 'bg-blue-50 dark:bg-blue-900/20' 
    },
    tool: { 
      icon: <Wrench className="w-4 h-4" />, 
      color: 'text-cyan-600 dark:text-cyan-400', 
      bg: 'bg-cyan-50 dark:bg-cyan-900/20' 
    },
    output: { 
      icon: <Terminal className="w-4 h-4" />, 
      color: 'text-gray-600 dark:text-gray-400', 
      bg: 'bg-gray-100 dark:bg-gray-800' 
    },
    llm: { 
      icon: <Bot className="w-4 h-4" />, 
      color: 'text-purple-600 dark:text-purple-400', 
      bg: 'bg-purple-50 dark:bg-purple-900/20' 
    },
    error: { 
      icon: <AlertCircle className="w-4 h-4" />, 
      color: 'text-red-600 dark:text-red-400', 
      bg: 'bg-red-50 dark:bg-red-900/20' 
    },
    success: { 
      icon: <CheckCircle2 className="w-4 h-4" />, 
      color: 'text-green-600 dark:text-green-400', 
      bg: 'bg-green-50 dark:bg-green-900/20' 
    },
  }
  
  const config = typeConfig[log.type] || typeConfig.info
  const time = new Date(log.timestamp).toLocaleTimeString('zh-CN', { hour12: false })
  const hasDetails = log.details && log.details.length > 0
  
  return (
    <div className={`rounded px-3 py-2 ${config.bg}`}>
      <div 
        className={`flex items-start gap-2 ${hasDetails ? 'cursor-pointer' : ''}`}
        onClick={() => hasDetails && setExpanded(!expanded)}
      >
        <span className={`mt-0.5 ${config.color}`}>{config.icon}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-gray-500 text-xs">{time}</span>
            {log.tool && (
              <span className="text-xs px-1.5 py-0.5 bg-gray-200 dark:bg-gray-700 rounded text-gray-600 dark:text-gray-300">
                {log.tool}
              </span>
            )}
          </div>
          <p className={`${config.color} break-words`}>{log.message}</p>
        </div>
        {hasDetails && (
          <span className="text-gray-500 mt-1">
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </span>
        )}
      </div>
      
      {expanded && log.details && (
        <div className="mt-2 ml-6 p-2 bg-white dark:bg-gray-800 rounded text-gray-600 dark:text-gray-300 text-xs whitespace-pre-wrap overflow-x-auto">
          {log.details}
        </div>
      )}
    </div>
  )
}

function AgentQuestionPanel({ scanId }: { scanId: string }) {
  const queryClient = useQueryClient()
  const [reply, setReply] = useState('')
  
  const { data: messagesData, isLoading } = useQuery({
    queryKey: ['scan-messages', scanId],
    queryFn: () => getScanMessages(scanId),
    refetchInterval: 2000,
  })
  
  const sendMutation = useMutation({
    mutationFn: (content: string) => sendScanMessage(scanId, content),
    onSuccess: () => {
      setReply('')
      queryClient.invalidateQueries({ queryKey: ['scan-messages', scanId] })
      queryClient.invalidateQueries({ queryKey: ['scan', scanId] })
    },
  })
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (reply.trim()) {
      sendMutation.mutate(reply.trim())
    }
  }
  
  if (isLoading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 mb-6 shadow">
        <div className="flex items-center gap-2 text-gray-500">
          <Loader2 className="w-5 h-5 animate-spin" />
          加载中...
        </div>
      </div>
    )
  }
  
  return (
    <div className="bg-orange-50 dark:bg-orange-900/20 border border-orange-200 dark:border-orange-800 rounded-lg p-6 mb-6">
      <div className="flex items-center gap-3 mb-4">
        <div className="flex items-center justify-center w-10 h-10 rounded-full bg-orange-100 dark:bg-orange-800">
          <Pause className="w-5 h-5 text-orange-600 dark:text-orange-400" />
        </div>
        <div>
          <h2 className="font-semibold text-orange-700 dark:text-orange-300">AI Agent 等待您的回复</h2>
          <p className="text-sm text-orange-600 dark:text-orange-400">请回答以下问题以继续扫描</p>
        </div>
      </div>
      
      {/* Message History */}
      {messagesData && messagesData.messages.length > 0 && (
        <div className="space-y-3 mb-4 max-h-64 overflow-y-auto">
          {messagesData.messages.map((msg) => (
            <div
              key={msg.id}
              className={`p-3 rounded-lg ${
                msg.role === 'agent'
                  ? 'bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700'
                  : 'bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800 ml-8'
              }`}
            >
              <div className="flex items-center gap-2 mb-1">
                {msg.role === 'agent' ? (
                  <Bot className="w-4 h-4 text-purple-500" />
                ) : (
                  <MessageCircle className="w-4 h-4 text-blue-500" />
                )}
                <span className="text-xs font-medium text-gray-500">
                  {msg.role === 'agent' ? 'AI Agent' : '您'}
                </span>
                <span className="text-xs text-gray-400">
                  {format(new Date(msg.created_at), 'HH:mm:ss')}
                </span>
              </div>
              <div className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                {msg.content}
              </div>
            </div>
          ))}
        </div>
      )}
      
      {/* Reply Input */}
      <form onSubmit={handleSubmit} className="flex gap-2">
        <input
          type="text"
          value={reply}
          onChange={(e) => setReply(e.target.value)}
          placeholder="输入您的回复..."
          disabled={sendMutation.isPending}
          className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 focus:outline-none focus:ring-2 focus:ring-orange-500 disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={!reply.trim() || sendMutation.isPending}
          className="flex items-center gap-2 px-4 py-2 bg-orange-600 hover:bg-orange-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <Send className="w-4 h-4" />
          {sendMutation.isPending ? '发送中...' : '发送'}
        </button>
      </form>
      
      {sendMutation.isError && (
        <p className="mt-2 text-sm text-red-500">
          发送失败，请重试
        </p>
      )}
    </div>
  )
}


// ============ Post-Scan Chat Panel ============

function ScanChatPanel({ scanId }: { scanId: string }) {
  const queryClient = useQueryClient()
  const [message, setMessage] = useState('')
  const [isExpanded, setIsExpanded] = useState(true)
  const chatEndRef = useRef<HTMLDivElement>(null)
  
  const { data: chatData, isLoading } = useQuery({
    queryKey: ['scan-chat', scanId],
    queryFn: () => getScanChatHistory(scanId),
  })
  
  const sendMutation = useMutation({
    mutationFn: (content: string) => sendScanChatMessage(scanId, content),
    onSuccess: () => {
      setMessage('')
      queryClient.invalidateQueries({ queryKey: ['scan-chat', scanId] })
    },
  })
  
  // Auto-scroll to bottom when new messages arrive
  useEffect(() => {
    if (chatEndRef.current && chatData?.messages.length) {
      chatEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [chatData?.messages])
  
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (message.trim() && !sendMutation.isPending) {
      sendMutation.mutate(message.trim())
    }
  }
  
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg mt-6 shadow overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full px-4 py-3 flex items-center justify-between border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750 transition-colors"
      >
        <div className="flex items-center gap-2">
          <MessageSquare className="w-5 h-5 text-purple-500" />
          <h2 className="font-semibold">继续分析</h2>
          <span className="text-xs text-gray-500">
            ({chatData?.messages.length || 0} 条对话)
          </span>
        </div>
        {isExpanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
      </button>
      
      {isExpanded && (
        <div className="p-4">
          {/* Description */}
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-4">
            扫描已完成，您可以继续向 AI 提问，对扫描结果进行更深入的分析。例如询问某个漏洞的详细信息、修复建议或攻击场景分析。
          </p>
          
          {/* Chat History */}
          {isLoading ? (
            <div className="flex items-center justify-center py-8 text-gray-500">
              <Loader2 className="w-5 h-5 animate-spin mr-2" />
              加载中...
            </div>
          ) : chatData?.messages.length ? (
            <div className="space-y-4 mb-4 max-h-96 overflow-y-auto">
              {chatData.messages.map((msg) => (
                <div
                  key={msg.id}
                  className={`flex gap-3 ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}
                >
                  <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${
                    msg.role === 'user' 
                      ? 'bg-blue-100 dark:bg-blue-900' 
                      : 'bg-purple-100 dark:bg-purple-900'
                  }`}>
                    {msg.role === 'user' ? (
                      <MessageCircle className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                    ) : (
                      <Brain className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                    )}
                  </div>
                  <div className={`max-w-[80%] p-3 rounded-lg ${
                    msg.role === 'user'
                      ? 'bg-blue-50 dark:bg-blue-900/30 border border-blue-200 dark:border-blue-800'
                      : 'bg-gray-100 dark:bg-gray-700'
                  }`}>
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-medium text-gray-500">
                        {msg.role === 'user' ? '您' : 'AI 分析师'}
                      </span>
                      <span className="text-xs text-gray-400">
                        {format(new Date(msg.created_at), 'HH:mm:ss')}
                      </span>
                    </div>
                    <div className="text-sm text-gray-700 dark:text-gray-300 whitespace-pre-wrap">
                      {msg.content}
                    </div>
                  </div>
                </div>
              ))}
              <div ref={chatEndRef} />
            </div>
          ) : (
            <div className="text-center py-6 text-gray-500 dark:text-gray-400">
              <MessageSquare className="w-8 h-8 mx-auto mb-2 opacity-50" />
              <p>开始提问，深入分析扫描结果</p>
            </div>
          )}
          
          {/* Input Form */}
          <form onSubmit={handleSubmit} className="flex gap-2">
            <input
              type="text"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="例如：这个SQL注入漏洞如何利用？该如何修复？"
              disabled={sendMutation.isPending}
              className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-900 focus:outline-none focus:ring-2 focus:ring-purple-500 disabled:opacity-50"
            />
            <button
              type="submit"
              disabled={!message.trim() || sendMutation.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {sendMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              {sendMutation.isPending ? '分析中...' : '发送'}
            </button>
          </form>
          
          {sendMutation.isError && (
            <p className="mt-2 text-sm text-red-500">
              发送失败，请重试
            </p>
          )}
          
          {/* Example Questions */}
          <div className="mt-4 flex flex-wrap gap-2">
            <span className="text-xs text-gray-500">快捷问题：</span>
            {[
              '总结主要安全风险',
              '最严重的漏洞是什么',
              '如何优先修复这些漏洞',
              '这些漏洞是否可被远程利用'
            ].map((q) => (
              <button
                key={q}
                onClick={() => setMessage(q)}
                disabled={sendMutation.isPending}
                className="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded text-gray-600 dark:text-gray-300 disabled:opacity-50"
              >
                {q}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
