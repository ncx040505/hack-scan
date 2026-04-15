import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Play, AlertTriangle, Settings, ChevronDown, ChevronUp, Bot, Info, X } from 'lucide-react'
import { createScan, ScanConfig, getPersonasBrief } from '../lib/api'

const scanTypeLabels: Record<string, { name: string; desc: string }> = {
  full: { name: '完整扫描', desc: '包含所有端口的全面扫描' },
  quick: { name: '仅扫描端口', desc: '仅扫描常用端口，不进行漏洞检测' },
  custom: { name: '自定义', desc: '手动配置扫描选项' },
}

// 判断目标是否为 URL（带协议）
function isUrl(target: string): boolean {
  return /^https?:\/\//i.test(target.trim())
}

// 从 URL 提取端口信息
function getUrlPort(target: string): string | null {
  try {
    const url = new URL(target.trim())
    if (url.port) {
      return url.port
    }
    // 默认端口
    return url.protocol === 'https:' ? '443' : '80'
  } catch {
    return null
  }
}

export default function NewScan() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('full')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [isUrlTarget, setIsUrlTarget] = useState(false)
  const [detectedPort, setDetectedPort] = useState<string | null>(null)
  const [config, setConfig] = useState<Partial<ScanConfig>>({
    enable_port_scan: true,
    enable_nuclei: true,
    scan_depth: 3,
    rate_limit: 10,
    ai_max_iterations: 0,  // 0 表示无限制
    ai_custom_prompt: '',
    ai_persona_id: null,  // 在 personas 加载后会自动设置为默认人格
  })

  // 目标历史记录管理
  const [targetHistory, setTargetHistory] = useState<string[]>([])
  const [showHistory, setShowHistory] = useState(false)

  // 从 localStorage 加载历史记录
  useEffect(() => {
    const saved = localStorage.getItem('scanTargetHistory')
    if (saved) {
      try {
        setTargetHistory(JSON.parse(saved))
      } catch (e) {
        console.error('Failed to load target history:', e)
      }
    }
  }, [])

  // 保存历史记录到 localStorage
  const saveTargetHistory = (history: string[]) => {
    setTargetHistory(history)
    localStorage.setItem('scanTargetHistory', JSON.stringify(history))
  }

  // 过滤匹配的历史记录
  const filteredHistory = targetHistory.filter(h =>
    h.toLowerCase().includes(target.toLowerCase()) && h !== target
  )

  // 从历史记录中删除项目
  const removeFromHistory = (item: string) => {
    const updated = targetHistory.filter(h => h !== item)
    saveTargetHistory(updated)
  }

  // 添加到历史记录
  const addToHistory = (value: string) => {
    if (!value.trim()) return
    const updated = [value, ...targetHistory.filter(h => h !== value)].slice(0, 20) // 保留最多20条
    saveTargetHistory(updated)
  }

  // 监听目标变化，自动检测是否为 URL
  useEffect(() => {
    const urlDetected = isUrl(target)
    setIsUrlTarget(urlDetected)

    if (urlDetected) {
      const port = getUrlPort(target)
      setDetectedPort(port)
      // URL 模式下默认禁用端口扫描
      setConfig(prev => ({ ...prev, enable_port_scan: false }))
    } else {
      setDetectedPort(null)
      // IP/域名模式下默认启用端口扫描
      setConfig(prev => ({ ...prev, enable_port_scan: true }))
    }
  }, [target])

  // 获取可用的人格列表
  const { data: personas } = useQuery({
    queryKey: ['personas-brief'],
    queryFn: getPersonasBrief,
  })

  // 在 personas 加载时，自动设置默认人格
  useEffect(() => {
    if (personas && personas.length > 0) {
      const defaultPersona = personas.find(p => p.is_default)
      if (defaultPersona && config.ai_persona_id === null) {
        setConfig(prev => ({ ...prev, ai_persona_id: defaultPersona.id }))
      }
    }
  }, [personas])

  const mutation = useMutation({
    mutationFn: () => createScan(target, scanType, config),
    onSuccess: (data) => {
      navigate(`/scans/${data.id}`)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return
    addToHistory(target)
    mutation.mutate()
  }

  const handleSelectHistory = (value: string) => {
    setTarget(value)
    setShowHistory(false)
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">新建扫描</h1>

      {/* Warning */}
      <div className="bg-yellow-100 dark:bg-yellow-900/50 border border-yellow-300 dark:border-yellow-700 rounded-lg p-4 mb-6 flex gap-3">
        <AlertTriangle className="w-6 h-6 text-yellow-600 dark:text-yellow-500 flex-shrink-0" />
        <div>
          <p className="font-semibold text-yellow-700 dark:text-yellow-500">重要提示</p>
          <p className="text-sm text-yellow-600 dark:text-yellow-200">
            仅扫描您拥有或获得明确授权的目标。未经授权的扫描可能违反法律。
          </p>
        </div>
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Target */}
        <div>
          <label className="block text-sm font-medium mb-2">目标 URL 或 IP</label>
          <div className="relative" onBlur={() => setTimeout(() => setShowHistory(false), 100)}>
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onFocus={() => setShowHistory(true)}
              placeholder="https://example.com 或 192.168.1.1"
              className="w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              required
            />
            {/* History Dropdown */}
            {showHistory && (targetHistory.length > 0 || target) && (
              <div className="absolute top-full left-0 right-0 mt-1 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg shadow-lg z-10 max-h-64 overflow-y-auto">
                {filteredHistory.length > 0 ? (
                  filteredHistory.slice(0, 5).map((item, index) => (
                    <div
                      key={index}
                      className="px-4 py-2 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center justify-between group"
                    >
                      <button
                        type="button"
                        onClick={() => handleSelectHistory(item)}
                        className="flex-1 text-left text-gray-700 dark:text-gray-300"
                      >
                        {item}
                      </button>
                      <button
                        type="button"
                        onMouseDown={e => e.preventDefault()}
                        onClick={() => removeFromHistory(item)}
                        className="p-1 opacity-0 group-hover:opacity-100 hover:text-red-500 transition-all"
                        title="删除历史记录"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  ))
                ) : targetHistory.length > 0 ? (
                  <div className="px-4 py-2 text-gray-500 dark:text-gray-400 text-sm">
                    未找到匹配的历史记录
                  </div>
                ) : null}
              </div>
            )}
          </div>
          {/* URL 检测提示 */}
          {isUrlTarget && (
            <div className="mt-2 flex items-start gap-2 text-sm text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30 p-2 rounded">
              <Info className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <span>
                检测到 URL 目标，将仅对端口 {detectedPort} 进行测试，已自动禁用端口扫描。
                如需扫描其他端口，请使用自定义模式手动开启。
              </span>
            </div>
          )}
        </div>

        {/* Scan Type */}
        <div>
          <label className="block text-sm font-medium mb-2">扫描类型</label>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            {Object.entries(scanTypeLabels).map(([type, { name }]) => (
              <button
                key={type}
                type="button"
                onClick={() => setScanType(type)}
                className={`px-4 py-3 rounded-lg border transition-colors ${scanType === type
                    ? 'bg-blue-600 border-blue-500 text-white'
                    : 'bg-white dark:bg-gray-800 border-gray-300 dark:border-gray-700 hover:border-gray-400 dark:hover:border-gray-600'
                  }`}
              >
                {name}
              </button>
            ))}
          </div>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-2">
            {scanTypeLabels[scanType]?.desc}
          </p>
        </div>

        {/* Custom Options */}
        {scanType === 'custom' && (
          <div className="space-y-4 p-4 bg-gray-100 dark:bg-gray-800 rounded-lg">
            <label className="flex items-center gap-3">
              <input
                type="checkbox"
                checked={config.enable_port_scan}
                onChange={e => setConfig({ ...config, enable_port_scan: e.target.checked })}
                className="w-4 h-4"
              />
              <span className="flex-1">
                启用端口扫描 (Nmap)
                {isUrlTarget && !config.enable_port_scan && (
                  <span className="ml-2 text-xs text-blue-500">(URL 模式已自动禁用)</span>
                )}
              </span>
            </label>

            <label className="flex items-center gap-3">
              <input
                type="checkbox"
                checked={config.enable_nuclei}
                onChange={e => setConfig({ ...config, enable_nuclei: e.target.checked })}
                className="w-4 h-4"
              />
              启用漏洞扫描 (Nuclei)
            </label>

            <div>
              <label className="block text-sm mb-1">速率限制 (请求/秒)</label>
              <input
                type="number"
                min="1"
                max="100"
                value={config.rate_limit}
                onChange={e => setConfig({ ...config, rate_limit: parseInt(e.target.value) })}
                className="w-24 bg-white dark:bg-gray-700 border border-gray-300 dark:border-gray-600 rounded px-3 py-1"
              />
            </div>
          </div>
        )}

        {/* Advanced AI Options */}
        <div className="border border-gray-300 dark:border-gray-700 rounded-lg overflow-hidden">
          <button
            type="button"
            onClick={() => setShowAdvanced(!showAdvanced)}
            className="w-full px-4 py-3 bg-gray-50 dark:bg-gray-800 flex items-center justify-between hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
          >
            <div className="flex items-center gap-2">
              <Settings className="w-5 h-5 text-gray-500" />
              <span className="font-medium">AI 高级选项</span>
            </div>
            {showAdvanced ? (
              <ChevronUp className="w-5 h-5 text-gray-500" />
            ) : (
              <ChevronDown className="w-5 h-5 text-gray-500" />
            )}
          </button>

          {showAdvanced && (
            <div className="p-4 space-y-4 bg-white dark:bg-gray-900">
              {/* AI Persona Selection */}
              <div>
                <label className="block text-sm font-medium mb-2">
                  <span className="flex items-center gap-2">
                    <Bot className="w-4 h-4 text-purple-500" />
                    AI 人格
                  </span>
                </label>
                <select
                  value={config.ai_persona_id || ''}
                  onChange={e => setConfig({ ...config, ai_persona_id: e.target.value })}
                  className="w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  {personas?.map(p => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                      {p.is_default ? ' (默认)' : ''}
                      {p.description ? ` - ${p.description}` : ''}
                    </option>
                  ))}
                </select>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  选择 AI Agent 的行为风格，可以在"AI 人格"页面管理
                </p>
              </div>

              {/* AI Custom Prompt */}
              <div>
                <label className="block text-sm font-medium mb-2">
                  自定义 AI 提示词 <span className="text-gray-400 font-normal">(可选)</span>
                </label>
                <textarea
                  value={config.ai_custom_prompt}
                  onChange={e => setConfig({ ...config, ai_custom_prompt: e.target.value })}
                  placeholder="输入额外的指示给 AI 代理，例如：&#10;- 重点测试 SQL 注入漏洞&#10;- 尝试绕过 WAF&#10;- 对登录接口进行暴力破解测试"
                  rows={4}
                  className="w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                />
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  AI 代理会根据这些指示调整测试策略（会追加到人格提示词之后）
                </p>
              </div>

              {/* AI Max Iterations */}
              <div>
                <label className="block text-sm font-medium mb-2">
                  最大迭代次数
                </label>
                <div className="flex items-center gap-3">
                  <input
                    type="number"
                    min="0"
                    max="1000"
                    value={config.ai_max_iterations}
                    onChange={e => setConfig({ ...config, ai_max_iterations: parseInt(e.target.value) || 0 })}
                    className="w-24 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <span className="text-sm text-gray-500 dark:text-gray-400">
                    {config.ai_max_iterations === 0 ? '无限制' : `最多 ${config.ai_max_iterations} 次`}
                  </span>
                </div>
                <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                  设置为 0 表示无限制，AI 将自行决定何时完成测试
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={mutation.isPending || !target.trim()}
          className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 dark:disabled:bg-gray-700 disabled:cursor-not-allowed text-white py-3 rounded-lg font-semibold flex items-center justify-center gap-2"
        >
          {mutation.isPending ? (
            '启动中...'
          ) : (
            <>
              <Play className="w-5 h-5" />
              开始扫描
            </>
          )}
        </button>

        {mutation.error && (
          <p className="text-red-500 text-sm">
            错误: {(mutation.error as Error).message}
          </p>
        )}
      </form>
    </div>
  )
}
