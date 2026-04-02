import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { format } from 'date-fns'
import { 
  Plus, Upload, Search, FileCode, FileText, Settings, Filter,
  Trash2, Eye, EyeOff, Edit, ChevronDown, ChevronUp, X, Check,
  Code, List, File, Tag, Zap
} from 'lucide-react'
import { getTools, uploadTool, deleteTool, updateTool, getToolContent, SecurityTool } from '../lib/api'

const toolTypeIcons: Record<string, React.ReactNode> = {
  script: <FileCode className="w-5 h-5" />,
  nuclei: <Code className="w-5 h-5" />,
  wordlist: <List className="w-5 h-5" />,
  config: <Settings className="w-5 h-5" />,
  skill: <Zap className="w-5 h-5" />,
}

const toolTypeLabels: Record<string, string> = {
  script: '脚本',
  nuclei: 'Nuclei 模板',
  wordlist: '字典',
  config: '配置文件',
  skill: 'AI Skill',
}

const categoryColors: Record<string, string> = {
  reconnaissance: 'bg-blue-600',
  vulnerability: 'bg-orange-600',
  exploitation: 'bg-red-600',
  post_exploitation: 'bg-purple-600',
  utility: 'bg-gray-600',
}

export default function Knowledgebase() {
  const queryClient = useQueryClient()
  const [showUpload, setShowUpload] = useState(false)
  const [filterType, setFilterType] = useState<string>('')
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedTool, setSelectedTool] = useState<SecurityTool | null>(null)
  const [showContent, setShowContent] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['tools', filterType],
    queryFn: () => getTools({ 
      limit: 100,
      tool_type: filterType || undefined,
      enabled_only: false
    }),
  })

  const deleteMutation = useMutation({
    mutationFn: deleteTool,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools'] })
      setSelectedTool(null)
    },
  })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => 
      updateTool(id, { is_enabled: enabled }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools'] })
    },
  })

  const tools = data?.items || []
  const filteredTools = tools.filter(t => 
    searchQuery === '' || 
    t.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    t.description?.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <div>
      {/* Header */}
      <div className="flex justify-between items-center mb-6">
        <div>
          <h1 className="text-2xl font-bold">知识库</h1>
          <p className="text-gray-500 dark:text-gray-400 text-sm">管理安全工具、脚本和模板</p>
        </div>
        <button
          onClick={() => setShowUpload(true)}
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center gap-2"
        >
          <Upload className="w-4 h-4" />
          上传工具
        </button>
      </div>

      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg p-4 mb-6 shadow">
        <div className="flex gap-4 items-center">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
            <input
              type="text"
              placeholder="搜索工具..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          
          <div className="flex gap-2">
            <button
              onClick={() => setFilterType('')}
              className={`px-3 py-2 rounded-lg text-sm ${filterType === '' ? 'bg-blue-600 text-white' : 'bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600'}`}
            >
              全部
            </button>
            {Object.entries(toolTypeLabels).map(([type, label]) => (
              <button
                key={type}
                onClick={() => setFilterType(type)}
                className={`px-3 py-2 rounded-lg text-sm flex items-center gap-1 ${filterType === type ? 'bg-blue-600 text-white' : 'bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600'}`}
              >
                {toolTypeIcons[type]}
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <StatCard label="总工具数" value={tools.length} />
        <StatCard label="脚本" value={tools.filter(t => t.tool_type === 'script').length} />
        <StatCard label="Nuclei 模板" value={tools.filter(t => t.tool_type === 'nuclei').length} />
        <StatCard label="字典" value={tools.filter(t => t.tool_type === 'wordlist').length} />
        <StatCard label="配置" value={tools.filter(t => t.tool_type === 'config').length} />
      </div>

      {/* Tools Grid */}
      {isLoading ? (
        <div className="text-center py-12 text-gray-500 dark:text-gray-400">加载中...</div>
      ) : filteredTools.length === 0 ? (
        <div className="text-center py-12 text-gray-500 dark:text-gray-400">
          <File className="w-12 h-12 mx-auto mb-2 opacity-50" />
          <p>暂无工具</p>
          <p className="text-sm">点击"上传工具"添加您的安全工具</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {filteredTools.map(tool => (
            <ToolCard 
              key={tool.id} 
              tool={tool} 
              onView={() => { setSelectedTool(tool); setShowContent(true); }}
              onToggle={(enabled) => toggleMutation.mutate({ id: tool.id, enabled })}
              onDelete={() => deleteMutation.mutate(tool.id)}
            />
          ))}
        </div>
      )}

      {/* Upload Modal */}
      {showUpload && (
        <UploadModal onClose={() => setShowUpload(false)} />
      )}

      {/* Content Modal */}
      {showContent && selectedTool && (
        <ContentModal tool={selectedTool} onClose={() => setShowContent(false)} />
      )}
    </div>
  )
}

function StatCard({ label, value }: { label: string; value: number }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 text-center shadow">
      <p className="text-2xl font-bold">{value}</p>
      <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
    </div>
  )
}

function ToolCard({ 
  tool, 
  onView, 
  onToggle, 
  onDelete 
}: { 
  tool: SecurityTool
  onView: () => void
  onToggle: (enabled: boolean) => void
  onDelete: () => void
}) {
  const [showActions, setShowActions] = useState(false)

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg p-4 shadow ${!tool.is_enabled ? 'opacity-60' : ''}`}>
      <div className="flex items-start justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-blue-600 dark:text-blue-400">{toolTypeIcons[tool.tool_type]}</span>
          <span className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded">
            {toolTypeLabels[tool.tool_type]}
          </span>
        </div>
        <div className="relative">
          <button 
            onClick={() => setShowActions(!showActions)}
            className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded"
          >
            <ChevronDown className="w-4 h-4" />
          </button>
          {showActions && (
            <div className="absolute right-0 top-8 bg-white dark:bg-gray-700 rounded-lg shadow-lg py-1 z-10 min-w-32 border border-gray-200 dark:border-gray-600">
              <button 
                onClick={() => { onView(); setShowActions(false); }}
                className="w-full px-3 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center gap-2"
              >
                <Eye className="w-4 h-4" /> 查看内容
              </button>
              <button 
                onClick={() => { onToggle(!tool.is_enabled); setShowActions(false); }}
                className="w-full px-3 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center gap-2"
              >
                {tool.is_enabled ? <EyeOff className="w-4 h-4" /> : <Check className="w-4 h-4" />}
                {tool.is_enabled ? '禁用' : '启用'}
              </button>
              <button 
                onClick={() => { onDelete(); setShowActions(false); }}
                className="w-full px-3 py-2 text-left text-sm hover:bg-gray-100 dark:hover:bg-gray-600 flex items-center gap-2 text-red-500"
              >
                <Trash2 className="w-4 h-4" /> 删除
              </button>
            </div>
          )}
        </div>
      </div>
      
      <h3 className="font-semibold mb-1">{tool.name}</h3>
      <p className="text-sm text-gray-500 dark:text-gray-400 line-clamp-2 mb-3">
        {tool.description || '暂无描述'}
      </p>
      
      <div className="flex items-center gap-2 text-xs text-gray-500 mb-2">
        <span>{tool.filename}</span>
        <span>•</span>
        <span>{formatFileSize(tool.file_size)}</span>
      </div>
      
      {tool.tags && tool.tags.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {tool.tags.slice(0, 3).map(tag => (
            <span key={tag} className="text-xs px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded-full">
              {tag}
            </span>
          ))}
          {tool.tags.length > 3 && (
            <span className="text-xs text-gray-500">+{tool.tags.length - 3}</span>
          )}
        </div>
      )}
    </div>
  )
}

function UploadModal({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [formData, setFormData] = useState({
    name: '',
    tool_type: 'script',
    description: '',
    category: '',
    tags: '',
    usage_instructions: '',
    author: '',
    version: '',
  })

  const uploadMutation = useMutation({
    mutationFn: async () => {
      if (!file) throw new Error('请选择文件')
      const data = new FormData()
      data.append('file', file)
      Object.entries(formData).forEach(([key, value]) => {
        if (value) data.append(key, value)
      })
      return uploadTool(data)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tools'] })
      onClose()
    },
  })

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const f = e.target.files?.[0]
    if (f) {
      setFile(f)
      if (!formData.name) {
        setFormData(prev => ({ ...prev, name: f.name.replace(/\.[^/.]+$/, '') }))
      }
    }
  }

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-lg max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-lg font-semibold">上传安全工具</h2>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded">
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <form onSubmit={(e) => { e.preventDefault(); uploadMutation.mutate(); }} className="p-4 space-y-4">
          {/* File Upload */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">文件 *</label>
            <div className="relative border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-4 text-center cursor-pointer hover:border-gray-400 dark:hover:border-gray-500 transition-colors">
              {file ? (
                <div className="flex items-center justify-center gap-2">
                  <File className="w-5 h-5 text-blue-500" />
                  <span>{file.name}</span>
                  <span className="text-gray-500">({formatFileSize(file.size)})</span>
                </div>
              ) : (
                <div>
                  <Upload className="w-8 h-8 mx-auto mb-2 text-gray-400" />
                  <p className="text-sm text-gray-500 dark:text-gray-400">点击或拖拽文件到此处</p>
                </div>
              )}
              <input
                type="file"
                onChange={handleFileChange}
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                accept=".py,.sh,.bash,.yaml,.yml,.txt,.lst,.dic,.json,.toml,.ini"
              />
            </div>
          </div>
          
          {/* Tool Type */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">工具类型 *</label>
            <select
              value={formData.tool_type}
              onChange={(e) => setFormData(prev => ({ ...prev, tool_type: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="script">脚本 (Python/Bash)</option>
              <option value="nuclei">Nuclei 模板</option>
              <option value="wordlist">字典文件</option>
              <option value="config">配置文件</option>
              <option value="skill">AI Skill</option>
            </select>
            {formData.tool_type === 'skill' && (
              <div className="mt-2 p-3 bg-blue-50 dark:bg-blue-900/30 rounded-lg text-sm">
                <p className="text-blue-700 dark:text-blue-300 font-medium mb-1">
                  💡 AI Skill 说明
                </p>
                <p className="text-blue-600 dark:text-blue-400 text-xs">
                  支持腾讯 SkillHub 压缩包 (.zip) 或其他 Markdown (.md)、Python (.py) 文件。AI 可自主决定何时调用这些技能。
                </p>
              </div>
            )}
          </div>
          
          {/* Name */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">名称 *</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="工具名称"
              required
            />
          </div>
          
          {/* Description */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">描述</label>
            <textarea
              value={formData.description}
              onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 h-20"
              placeholder="工具描述..."
            />
          </div>
          
          {/* Category */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">分类</label>
            <select
              value={formData.category}
              onChange={(e) => setFormData(prev => ({ ...prev, category: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="">选择分类</option>
              <option value="reconnaissance">侦察 (Reconnaissance)</option>
              <option value="vulnerability">漏洞扫描 (Vulnerability)</option>
              <option value="exploitation">利用 (Exploitation)</option>
              <option value="post_exploitation">后渗透 (Post-Exploitation)</option>
              <option value="utility">实用工具 (Utility)</option>
            </select>
          </div>
          
          {/* Tags */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">标签 (逗号分隔)</label>
            <input
              type="text"
              value={formData.tags}
              onChange={(e) => setFormData(prev => ({ ...prev, tags: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              placeholder="web, sql, xss"
            />
          </div>
          
          {/* Usage Instructions */}
          <div>
            <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">使用说明</label>
            <textarea
              value={formData.usage_instructions}
              onChange={(e) => setFormData(prev => ({ ...prev, usage_instructions: e.target.value }))}
              className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500 h-20"
              placeholder="如何使用这个工具..."
            />
          </div>
          
          {/* Author & Version */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">作者</label>
              <input
                type="text"
                value={formData.author}
                onChange={(e) => setFormData(prev => ({ ...prev, author: e.target.value }))}
                className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm text-gray-500 dark:text-gray-400 mb-1">版本</label>
              <input
                type="text"
                value={formData.version}
                onChange={(e) => setFormData(prev => ({ ...prev, version: e.target.value }))}
                className="w-full bg-gray-100 dark:bg-gray-700 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                placeholder="1.0.0"
              />
            </div>
          </div>
          
          {/* Error */}
          {uploadMutation.isError && (
            <div className="text-red-500 text-sm">
              上传失败: {
                // @ts-expect-error axios error response
                uploadMutation.error?.response?.data?.detail || 
                (uploadMutation.error as Error).message
              }
            </div>
          )}
          
          {/* Submit */}
          <div className="flex justify-end gap-2 pt-4">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-gray-200 dark:bg-gray-700 hover:bg-gray-300 dark:hover:bg-gray-600"
            >
              取消
            </button>
            <button
              type="submit"
              disabled={!file || !formData.name || uploadMutation.isPending}
              className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
            >
              {uploadMutation.isPending ? '上传中...' : '上传'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

function ContentModal({ tool, onClose }: { tool: SecurityTool; onClose: () => void }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['tool-content', tool.id],
    queryFn: () => getToolContent(tool.id),
  })

  return (
    <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700">
          <div>
            <h2 className="text-lg font-semibold">{tool.name}</h2>
            <p className="text-sm text-gray-500 dark:text-gray-400">{tool.filename}</p>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-gray-700 rounded">
            <X className="w-5 h-5" />
          </button>
        </div>
        
        <div className="flex-1 overflow-auto p-4">
          {isLoading ? (
            <div className="text-center py-8 text-gray-500 dark:text-gray-400">加载中...</div>
          ) : error ? (
            <div className="text-center py-8 text-red-500">
              无法加载文件内容
            </div>
          ) : (
            <pre className="bg-gray-100 dark:bg-gray-900 rounded-lg p-4 text-sm font-mono overflow-x-auto whitespace-pre-wrap">
              {data?.content}
            </pre>
          )}
        </div>
        
        {tool.usage_instructions && (
          <div className="border-t border-gray-200 dark:border-gray-700 p-4">
            <h3 className="font-semibold mb-2">使用说明</h3>
            <p className="text-sm text-gray-600 dark:text-gray-300 whitespace-pre-wrap">
              {tool.usage_instructions}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

function formatFileSize(bytes: number | null): string {
  if (!bytes) return '未知'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}
