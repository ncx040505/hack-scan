import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import { AlertTriangle, Clock, CheckCircle, Brain, Loader2, ChevronDown, ChevronUp, ChevronRight, Terminal, Bot, Wrench, AlertCircle, CheckCircle2, Info, XCircle, Trash2, MessageCircle, Send, Pause, MessageSquare, Server, Eye, EyeOff, Shield, FileText, Route, ShieldCheck, RefreshCw } from 'lucide-react'
import { getScan, getVulnerabilities, getScanProgress, getScanLogs, cancelScan, deleteScan, getScanMessages, sendScanMessage, getScanChatHistory, sendScanChatMessage, getAttackPath, Vulnerability, ScanLogEntry, AttackPathData, AttackPhase as APIAttackPhase, AttackChain, RiskAssessment } from '../lib/api'
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

// Tab 类型定义
type TabType = 'vulnerabilities' | 'attack-dialog' | 'attack-path' | 'report' | 'remediation'

interface TabItem {
  id: TabType
  label: string
  icon: React.ReactNode
}

// Tab 配置
const tabs: TabItem[] = [
  { id: 'vulnerabilities', label: '漏洞信息', icon: <Shield className="w-4 h-4" /> },
  { id: 'attack-dialog', label: '攻击对话', icon: <Terminal className="w-4 h-4" /> },
  { id: 'attack-path', label: '攻击路径', icon: <Route className="w-4 h-4" /> },
  { id: 'report', label: '漏洞报告', icon: <FileText className="w-4 h-4" /> },
  { id: 'remediation', label: '漏洞加固', icon: <ShieldCheck className="w-4 h-4" /> },
]

export default function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<TabType>('vulnerabilities')
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

      {/* Tab Navigation */}
      <div className="mb-6 border-b border-gray-200 dark:border-gray-700 overflow-x-auto">
        <nav className="flex space-x-1 min-w-max" aria-label="Tabs">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`
                flex items-center gap-2 px-4 py-3 text-sm font-medium whitespace-nowrap
                border-b-2 transition-colors duration-200
                ${activeTab === tab.id
                  ? 'border-blue-500 text-blue-600 dark:text-blue-400'
                  : 'border-transparent text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300 hover:border-gray-300 dark:hover:border-gray-600'
                }
              `}
            >
              {tab.icon}
              <span>{tab.label}</span>
            </button>
          ))}
        </nav>
      </div>

      {/* Tab Content */}
      <div className="min-h-[400px]">
        {/* Tab 1: 漏洞信息 */}
        {activeTab === 'vulnerabilities' && (
          <TabVulnerabilities
            scan={scan}
            vulns={vulns}
            vulnsLoading={vulnsLoading}
            showVulns={showVulns}
            setShowVulns={setShowVulns}
          />
        )}

        {/* Tab 2: 攻击对话 */}
        {activeTab === 'attack-dialog' && (
          <TabAttackDialog
            scanId={scanId!}
            scan={scan}
            logs={logs}
            showLogs={showLogs}
            setShowLogs={setShowLogs}
            logsEndRef={logsEndRef}
            isActive={isActive}
          />
        )}

        {/* Tab 3: 攻击路径 */}
        {activeTab === 'attack-path' && (
          <TabAttackPath scan={scan} vulns={vulns} />
        )}

        {/* Tab 4: 漏洞报告 */}
        {activeTab === 'report' && (
          <TabReport scan={scan} vulns={vulns} />
        )}

        {/* Tab 5: 漏洞加固 */}
        {activeTab === 'remediation' && (
          <TabRemediation scanId={scanId!} scan={scan} vulns={vulns} />
        )}
      </div>
    </div>
  )
}

// ============ Tab Content Components ============

function TabVulnerabilities({
  scan,
  vulns,
  vulnsLoading,
  showVulns,
  setShowVulns,
}: {
  scan: any
  vulns: any
  vulnsLoading: boolean
  showVulns: boolean
  setShowVulns: (v: boolean) => void
}) {
  const openPorts = vulns?.items.filter((v: Vulnerability) => v.name.startsWith('Open port:')) || []
  const actualVulns = vulns?.items.filter((v: Vulnerability) => !v.name.startsWith('Open port:')) || []

  if (scan.status !== 'COMPLETED' && scan.status !== 'FAILED' && scan.status !== 'CANCELLED') {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <Shield className="w-12 h-12 mx-auto mb-4 text-gray-400" />
        <p className="text-gray-500 dark:text-gray-400">扫描进行中，完成后将在此显示漏洞信息</p>
      </div>
    )
  }

  return (
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
              {openPorts.map((port: Vulnerability) => (
                <PortCard key={port.id} port={port} />
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Stats - only count actual vulnerabilities */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <StatBox label="漏洞数" value={actualVulns.length} />
        <StatBox
          label="严重"
          value={actualVulns.filter((v: Vulnerability) => v.severity === 'critical').length}
          color="text-red-500"
        />
        <StatBox
          label="高危"
          value={actualVulns.filter((v: Vulnerability) => v.severity === 'high').length}
          color="text-orange-500"
        />
        <StatBox
          label="中危"
          value={actualVulns.filter((v: Vulnerability) => v.severity === 'medium').length}
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
            {actualVulns.map((vuln: Vulnerability) => (
              <VulnRow key={vuln.id} vuln={vuln} />
            ))}
          </div>
        )}
      </div>
    </>
  )
}

function TabAttackDialog({
  scanId,
  scan,
  logs,
  showLogs,
  setShowLogs,
  logsEndRef,
  isActive,
}: {
  scanId: string
  scan: any
  logs: ScanLogEntry[]
  showLogs: boolean
  setShowLogs: (v: boolean) => void
  logsEndRef: React.RefObject<HTMLDivElement>
  isActive: boolean
}) {
  return (
    <>
      {/* Paused - Agent asking user */}
      {scan.status === 'PAUSED' && (
        <AgentQuestionPanel scanId={scanId} />
      )}

      {/* Real-time Logs */}
      {(isActive || logs.length > 0) && (
        <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow">
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
            <div className="max-h-[70vh] overflow-y-auto p-4 space-y-2 bg-gray-50 dark:bg-gray-900 font-mono text-sm transition-all duration-300">
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

      {/* 没有日志时的空状态 */}
      {!isActive && logs.length === 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
          <Terminal className="w-12 h-12 mx-auto mb-4 text-gray-400" />
          <p className="text-gray-500 dark:text-gray-400">暂无执行日志</p>
        </div>
      )}
    </>
  )
}

// 攻击阶段定义（本地渲染用）
interface AttackPhaseUI {
  id: string
  name: string
  description: string
  icon: React.ReactNode
  color: string
  bgColor: string
  items: AttackItem[]
}

interface AttackItem {
  id: string
  name: string
  severity?: string
  location?: string
  description?: string
}

// 阶段样式配置
const phaseStyles: Record<string, { icon: React.ReactNode; color: string; bgColor: string }> = {
  recon: {
    icon: <Eye className="w-5 h-5" />,
    color: 'text-blue-600 dark:text-blue-400',
    bgColor: 'bg-blue-50 dark:bg-blue-900/30 border-blue-200 dark:border-blue-800',
  },
  vuln: {
    icon: <AlertTriangle className="w-5 h-5" />,
    color: 'text-orange-600 dark:text-orange-400',
    bgColor: 'bg-orange-50 dark:bg-orange-900/30 border-orange-200 dark:border-orange-800',
  },
  exploit: {
    icon: <Wrench className="w-5 h-5" />,
    color: 'text-red-600 dark:text-red-400',
    bgColor: 'bg-red-50 dark:bg-red-900/30 border-red-200 dark:border-red-800',
  },
  impact: {
    icon: <AlertCircle className="w-5 h-5" />,
    color: 'text-purple-600 dark:text-purple-400',
    bgColor: 'bg-purple-50 dark:bg-purple-900/30 border-purple-200 dark:border-purple-800',
  },
}

function TabAttackPath({ scan, vulns }: { scan: any; vulns: any }) {
  const queryClient = useQueryClient()

  // 使用后端 API 获取攻击路径分析
  const { data: attackPathResponse, isLoading, error, refetch } = useQuery({
    queryKey: ['attack-path', scan.id],
    queryFn: () => getAttackPath(scan.id),
    enabled: scan.status === 'COMPLETED' && vulns?.items?.length > 0,
    staleTime: 5 * 60 * 1000, // 5分钟缓存
  })

  const [isRefreshing, setIsRefreshing] = useState(false)

  const handleRefresh = async () => {
    setIsRefreshing(true)
    try {
      await getAttackPath(scan.id, true) // 强制刷新
      queryClient.invalidateQueries({ queryKey: ['attack-path', scan.id] })
    } finally {
      setIsRefreshing(false)
    }
  }

  // 加载状态
  if (isLoading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <Loader2 className="w-12 h-12 mx-auto mb-4 text-blue-500 animate-spin" />
        <h3 className="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-300">正在分析攻击路径...</h3>
        <p className="text-gray-500 dark:text-gray-400">AI 正在基于扫描结果生成攻击路径分析</p>
      </div>
    )
  }

  // 扫描未完成
  if (scan.status !== 'COMPLETED') {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <Route className="w-16 h-16 mx-auto mb-4 text-gray-400" />
        <h3 className="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-300">攻击路径分析</h3>
        <p className="text-gray-500 dark:text-gray-400">扫描完成后将自动生成攻击路径分析</p>
      </div>
    )
  }

  // 没有漏洞
  if (!vulns?.items?.length) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-500" />
        <h3 className="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-300">未发现漏洞</h3>
        <p className="text-gray-500 dark:text-gray-400">扫描未发现安全问题，目标相对安全</p>
      </div>
    )
  }

  // 错误状态
  if (error) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <XCircle className="w-16 h-16 mx-auto mb-4 text-red-500" />
        <h3 className="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-300">分析失败</h3>
        <p className="text-gray-500 dark:text-gray-400 mb-4">无法生成攻击路径分析</p>
        <button
          onClick={() => refetch()}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          重试
        </button>
      </div>
    )
  }

  const attackPath = attackPathResponse?.data
  if (!attackPath) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow">
        <Route className="w-16 h-16 mx-auto mb-4 text-gray-400" />
        <h3 className="text-lg font-semibold mb-2 text-gray-700 dark:text-gray-300">暂无数据</h3>
        <p className="text-gray-500 dark:text-gray-400">攻击路径分析数据不可用</p>
      </div>
    )
  }

  const { phases, attack_chains, risk_assessment } = attackPath

  // 将 API 数据转换为 UI 格式
  const phasesUI: AttackPhaseUI[] = phases.map(phase => ({
    ...phase,
    ...phaseStyles[phase.id] || phaseStyles.vuln,
    items: phase.items.map(item => ({
      id: item.id,
      name: item.name,
      severity: item.severity,
      description: item.details,
    })),
  }))

  // 风险等级配置
  const riskConfig: Record<string, { label: string; color: string; bg: string }> = {
    critical: { label: '极高风险', color: 'text-red-600', bg: 'bg-red-100 dark:bg-red-900/50' },
    high: { label: '高风险', color: 'text-orange-600', bg: 'bg-orange-100 dark:bg-orange-900/50' },
    medium: { label: '中等风险', color: 'text-yellow-600', bg: 'bg-yellow-100 dark:bg-yellow-900/50' },
    low: { label: '低风险', color: 'text-green-600', bg: 'bg-green-100 dark:bg-green-900/50' },
  }

  const riskLevel = risk_assessment.overall_risk || 'low'

  return (
    <div className="space-y-6">
      {/* 风险概览 */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <Route className="w-5 h-5 text-blue-500" />
            攻击路径分析
            {attackPathResponse?.cached && (
              <span className="text-xs text-gray-400 font-normal">(缓存)</span>
            )}
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="p-2 text-gray-500 hover:text-blue-500 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
              title="重新分析"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
            </button>
            <div className={`px-3 py-1 rounded-full text-sm font-medium ${riskConfig[riskLevel]?.bg || ''} ${riskConfig[riskLevel]?.color || ''}`}>
              {riskConfig[riskLevel]?.label || '未知风险'}
            </div>
          </div>
        </div>

        {/* 风险评分 */}
        <div className="flex items-center gap-4 mb-4">
          <div className="flex-1">
            <div className="flex items-center justify-between text-sm mb-1">
              <span className="text-gray-500">风险评分</span>
              <span className="font-semibold">{risk_assessment.risk_score}/100</span>
            </div>
            <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all ${risk_assessment.risk_score >= 80 ? 'bg-red-500' :
                    risk_assessment.risk_score >= 60 ? 'bg-orange-500' :
                      risk_assessment.risk_score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
                  }`}
                style={{ width: `${risk_assessment.risk_score}%` }}
              />
            </div>
          </div>
        </div>

        <p className="text-gray-600 dark:text-gray-400 text-sm">
          {risk_assessment.summary}
        </p>
      </div>

      {/* 攻击阶段可视化 */}
      <div className="relative">
        <div className="absolute top-0 bottom-0 left-8 w-0.5 bg-gray-200 dark:bg-gray-700 hidden md:block" />
        <div className="space-y-4">
          {phasesUI.map((phase, index) => (
            <AttackPhaseCard key={phase.id} phase={phase} index={index} />
          ))}
        </div>
      </div>

      {/* 攻击链 */}
      {attack_chains.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-500" />
            攻击链分析
          </h3>
          <div className="space-y-4">
            {attack_chains.map((chain) => (
              <AttackChainCard key={chain.id} chain={chain} />
            ))}
          </div>
        </div>
      )}

      {/* 安全建议 */}
      {risk_assessment.recommendations.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
          <h3 className="font-semibold mb-4 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-green-500" />
            安全建议
          </h3>
          <ul className="space-y-2">
            {risk_assessment.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-gray-600 dark:text-gray-300">
                <CheckCircle2 className="w-4 h-4 text-green-500 mt-0.5 shrink-0" />
                {rec}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

// 攻击链卡片组件
function AttackChainCard({ chain }: { chain: AttackChain }) {
  const [expanded, setExpanded] = useState(false)

  const impactColors: Record<string, string> = {
    critical: 'bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300',
    high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/50 dark:text-orange-300',
    medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/50 dark:text-yellow-300',
    low: 'bg-green-100 text-green-700 dark:bg-green-900/50 dark:text-green-300',
  }

  const likelihoodLabels: Record<string, string> = {
    high: '高可能性',
    medium: '中可能性',
    low: '低可能性',
  }

  return (
    <div className="border border-gray-200 dark:border-gray-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <Wrench className="w-5 h-5 text-red-500" />
          <div className="text-left">
            <h4 className="font-medium">{chain.name}</h4>
            <p className="text-sm text-gray-500 dark:text-gray-400">{chain.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className={`px-2 py-1 rounded text-xs ${impactColors[chain.impact] || ''}`}>
            {chain.impact.toUpperCase()}
          </span>
          <span className="text-xs text-gray-500">
            {likelihoodLabels[chain.likelihood] || chain.likelihood}
          </span>
          {expanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </div>
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-gray-100 dark:border-gray-700">
          <div className="pt-4 space-y-3">
            {chain.steps.map((step, i) => (
              <div key={i} className="flex items-start gap-3">
                <div className="w-6 h-6 rounded-full bg-blue-100 dark:bg-blue-900/50 text-blue-600 dark:text-blue-400 flex items-center justify-center text-xs font-bold shrink-0">
                  {step.order}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-sm">{step.action}</p>
                  {step.vulnerability && (
                    <p className="text-xs text-orange-600 dark:text-orange-400">利用: {step.vulnerability}</p>
                  )}
                  <p className="text-xs text-gray-500 dark:text-gray-400">{step.result}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// 攻击阶段卡片组件
function AttackPhaseCard({ phase, index }: { phase: AttackPhaseUI; index: number }) {
  const [expanded, setExpanded] = useState(index < 2) // 前两个默认展开

  return (
    <div className={`relative md:ml-12 bg-white dark:bg-gray-800 rounded-lg shadow border ${phase.bgColor}`}>
      {/* 时间线节点 */}
      <div className={`absolute -left-12 top-4 w-6 h-6 rounded-full bg-white dark:bg-gray-800 border-2 items-center justify-center hidden md:flex ${phase.color} border-current`}>
        <span className="text-xs font-bold">{index + 1}</span>
      </div>

      {/* 头部 */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors rounded-t-lg"
      >
        <div className="flex items-center gap-3">
          <div className={`p-2 rounded-lg ${phase.bgColor} ${phase.color}`}>
            {phase.icon}
          </div>
          <div className="text-left">
            <h3 className="font-semibold">{phase.name}</h3>
            <p className="text-sm text-gray-500 dark:text-gray-400">{phase.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-500 bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded">
            {phase.items.length} 项
          </span>
          {expanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </div>
      </button>

      {/* 内容 */}
      {expanded && phase.items.length > 0 && (
        <div className="px-4 pb-4 space-y-2">
          {phase.items.slice(0, 10).map((item) => (
            <div
              key={item.id}
              className="p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
            >
              <div className="flex items-start gap-2">
                {item.severity && <SeverityBadge severity={item.severity as any} />}
                <div className="flex-1 min-w-0">
                  <p className="font-medium text-sm">{item.name}</p>
                  {item.location && (
                    <p className="text-xs text-gray-500 dark:text-gray-400 truncate">{item.location}</p>
                  )}
                  {item.description && (
                    <p className="text-xs text-gray-600 dark:text-gray-300 mt-1 line-clamp-2">{item.description}</p>
                  )}
                </div>
              </div>
            </div>
          ))}
          {phase.items.length > 10 && (
            <p className="text-sm text-gray-500 text-center py-2">
              还有 {phase.items.length - 10} 项...
            </p>
          )}
        </div>
      )}

      {expanded && phase.items.length === 0 && (
        <div className="px-4 pb-4">
          <p className="text-sm text-gray-500 dark:text-gray-400 text-center py-4">
            未发现相关内容
          </p>
        </div>
      )}
    </div>
  )
}

// 攻击路径流程图组件
function AttackPathFlow({ vuln, openPorts }: { vuln: Vulnerability; openPorts: Vulnerability[] }) {
  // 尝试匹配相关端口
  const relatedPort = openPorts.find(p =>
    vuln.location?.includes(p.location?.split(':')[1]?.split('/')[0] || 'xxx')
  )

  return (
    <div className="p-4 bg-gray-50 dark:bg-gray-700/30 rounded-lg">
      <div className="flex items-center gap-2 mb-3">
        <SeverityBadge severity={vuln.severity} />
        <span className="font-medium">{vuln.name}</span>
      </div>

      {/* 流程图 */}
      <div className="flex items-center gap-2 flex-wrap text-sm">
        <div className="flex items-center gap-1 px-3 py-1.5 bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300 rounded-lg">
          <Server className="w-4 h-4" />
          <span>目标主机</span>
        </div>
        <ChevronRight className="w-4 h-4 text-gray-400" />

        {relatedPort && (
          <>
            <div className="flex items-center gap-1 px-3 py-1.5 bg-cyan-100 dark:bg-cyan-900/50 text-cyan-700 dark:text-cyan-300 rounded-lg">
              <Terminal className="w-4 h-4" />
              <span>{relatedPort.location || '开放端口'}</span>
            </div>
            <ChevronRight className="w-4 h-4 text-gray-400" />
          </>
        )}

        <div className="flex items-center gap-1 px-3 py-1.5 bg-orange-100 dark:bg-orange-900/50 text-orange-700 dark:text-orange-300 rounded-lg">
          <AlertTriangle className="w-4 h-4" />
          <span className="truncate max-w-[150px]" title={vuln.name}>{vuln.name}</span>
        </div>
        <ChevronRight className="w-4 h-4 text-gray-400" />

        <div className="flex items-center gap-1 px-3 py-1.5 bg-red-100 dark:bg-red-900/50 text-red-700 dark:text-red-300 rounded-lg">
          <XCircle className="w-4 h-4" />
          <span>系统入侵</span>
        </div>
      </div>

      {vuln.location && (
        <p className="text-xs text-gray-500 dark:text-gray-400 mt-2">
          位置: {vuln.location}
        </p>
      )}
    </div>
  )
}

function TabReport({ scan, vulns }: { scan: any; vulns: any }) {
  const actualVulns = vulns?.items.filter((v: Vulnerability) => !v.name.startsWith('Open port:')) || []

  return (
    <>
      {/* LLM Summary */}
      {scan.llm_summary && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 mb-6 shadow">
          <div className="flex items-center gap-2 mb-3">
            <Brain className="w-5 h-5 text-purple-500" />
            <h2 className="font-semibold">AI 分析摘要</h2>
          </div>
          <p className="text-gray-600 dark:text-gray-300 whitespace-pre-wrap">{scan.llm_summary}</p>
        </div>
      )}

      {/* Risk Score */}
      {scan.llm_risk_score !== null && scan.llm_risk_score !== undefined && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-6 mb-6 shadow">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-orange-500" />
              <h2 className="font-semibold">风险评分</h2>
            </div>
            <RiskScore score={scan.llm_risk_score} />
          </div>
          <div className="mt-4">
            <div className="h-3 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${scan.llm_risk_score >= 80 ? 'bg-red-500' :
                    scan.llm_risk_score >= 60 ? 'bg-orange-500' :
                      scan.llm_risk_score >= 40 ? 'bg-yellow-500' :
                        'bg-green-500'
                  }`}
                style={{ width: `${scan.llm_risk_score}%` }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Vulnerability Stats */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 shadow">
        <div className="flex items-center gap-2 mb-4">
          <Shield className="w-5 h-5 text-blue-500" />
          <h2 className="font-semibold">漏洞统计</h2>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
            <p className="text-3xl font-bold text-gray-900 dark:text-white">{actualVulns.length}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">总漏洞数</p>
          </div>
          <div className="text-center p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
            <p className="text-3xl font-bold text-red-500">{actualVulns.filter((v: Vulnerability) => v.severity === 'critical').length}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">严重</p>
          </div>
          <div className="text-center p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
            <p className="text-3xl font-bold text-orange-500">{actualVulns.filter((v: Vulnerability) => v.severity === 'high').length}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">高危</p>
          </div>
          <div className="text-center p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
            <p className="text-3xl font-bold text-yellow-500">{actualVulns.filter((v: Vulnerability) => v.severity === 'medium').length}</p>
            <p className="text-sm text-gray-500 dark:text-gray-400">中危</p>
          </div>
        </div>
      </div>

      {/* 没有报告时的空状态 */}
      {!scan.llm_summary && scan.llm_risk_score === null && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow mt-6">
          <FileText className="w-12 h-12 mx-auto mb-4 text-gray-400" />
          <p className="text-gray-500 dark:text-gray-400">扫描完成后将生成 AI 分析报告</p>
        </div>
      )}
    </>
  )
}

function TabRemediation({ scanId, scan, vulns }: { scanId: string; scan: any; vulns: any }) {
  const actualVulns = vulns?.items.filter((v: Vulnerability) => !v.name.startsWith('Open port:')) || []
  const vulnsWithRemediation = actualVulns.filter((v: Vulnerability) => v.llm_remediation)

  return (
    <>
      {/* Remediation Summary */}
      {vulnsWithRemediation.length > 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow mb-6">
          <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-green-500" />
            <h2 className="font-semibold">修复建议汇总</h2>
            <span className="text-sm text-gray-500">({vulnsWithRemediation.length} 条)</span>
          </div>
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {vulnsWithRemediation.map((vuln: Vulnerability) => (
              <div key={vuln.id} className="p-4">
                <div className="flex items-start gap-3">
                  <SeverityBadge severity={vuln.severity} />
                  <div className="flex-1">
                    <h3 className="font-medium text-gray-900 dark:text-white">{vuln.name}</h3>
                    <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">{vuln.location}</p>
                    <div className="mt-3 p-3 bg-green-50 dark:bg-green-900/20 rounded-lg border border-green-200 dark:border-green-800">
                      <div className="flex items-center gap-1 text-green-600 dark:text-green-400 mb-1 text-sm font-medium">
                        <ShieldCheck className="w-4 h-4" />
                        修复建议
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-300">{vuln.llm_remediation}</p>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 没有修复建议时的空状态 */}
      {vulnsWithRemediation.length === 0 && (
        <div className="bg-white dark:bg-gray-800 rounded-lg p-8 text-center shadow mb-6">
          <ShieldCheck className="w-12 h-12 mx-auto mb-4 text-gray-400" />
          <p className="text-gray-500 dark:text-gray-400">
            {scan.status === 'COMPLETED' ? '暂无修复建议' : '扫描完成后将生成修复建议'}
          </p>
        </div>
      )}

      {/* Post-Scan Chat - 扫描完成后的对话分析 */}
      {(scan.status === 'COMPLETED' || scan.status === 'FAILED' || scan.status === 'CANCELLED') && (
        <ScanChatPanel scanId={scanId} />
      )}
    </>
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
    <div className={`flex-1 text-center py-2 px-3 rounded ${done ? 'bg-green-100 dark:bg-green-900/50 text-green-600 dark:text-green-400' :
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
              className={`p-3 rounded-lg ${msg.role === 'agent'
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
                  <div className={`flex-shrink-0 w-8 h-8 rounded-full flex items-center justify-center ${msg.role === 'user'
                      ? 'bg-blue-100 dark:bg-blue-900'
                      : 'bg-purple-100 dark:bg-purple-900'
                    }`}>
                    {msg.role === 'user' ? (
                      <MessageCircle className="w-4 h-4 text-blue-600 dark:text-blue-400" />
                    ) : (
                      <Brain className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                    )}
                  </div>
                  <div className={`max-w-[80%] p-3 rounded-lg ${msg.role === 'user'
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
