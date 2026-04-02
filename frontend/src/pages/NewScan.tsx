import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { Play, AlertTriangle, Settings, ChevronDown, ChevronUp, Bot } from 'lucide-react'
import { createScan, ScanConfig, getPersonasBrief } from '../lib/api'

const scanTypeLabels: Record<string, { name: string; desc: string }> = {
  full: { name: '完整扫描', desc: '包含所有端口的全面扫描' },
  custom: { name: '自定义', desc: '手动配置扫描选项' },
  quick: { name: '仅扫描端口', desc: '仅扫描常用端口，不进行漏洞检测' },
}

export default function NewScan() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('full')
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [config, setConfig] = useState<Partial<ScanConfig>>({
    enable_port_scan: true,
    enable_nuclei: true,
    scan_depth: 3,
    rate_limit: 10,
    ai_max_iterations: 0,  // 0 表示无限制
    ai_custom_prompt: '',
    ai_persona_id: null,  // null 表示使用默认人格
  })

  // 获取可用的人格列表
  const { data: personas } = useQuery({
    queryKey: ['personas-brief'],
    queryFn: getPersonasBrief,
  })

  const mutation = useMutation({
    mutationFn: () => createScan(target, scanType, config),
    onSuccess: (data) => {
      navigate(`/scans/${data.id}`)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return
    mutation.mutate()
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
          <input
            type="text"
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder="https://example.com 或 192.168.1.1"
            className="w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            required
          />
        </div>

        {/* Scan Type */}
        <div>
          <label className="block text-sm font-medium mb-2">扫描类型</label>
          <div className="grid grid-cols-3 gap-3">
            {Object.entries(scanTypeLabels).map(([type, { name }]) => (
              <button
                key={type}
                type="button"
                onClick={() => setScanType(type)}
                className={`px-4 py-3 rounded-lg border transition-colors ${
                  scanType === type
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
              启用端口扫描 (Nmap)
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
                  onChange={e => setConfig({ ...config, ai_persona_id: e.target.value || null })}
                  className="w-full bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-700 rounded-lg px-4 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="">使用默认人格</option>
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
