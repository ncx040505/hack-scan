import axios from 'axios'

// Default to same-origin path so remote users do not call their own localhost.
const API_BASE = import.meta.env.VITE_API_URL || '/api/v1'

export const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types
export interface ScanConfig {
  enable_port_scan: boolean
  enable_web_scan: boolean
  enable_nuclei: boolean
  custom_ports: number[]
  scan_depth: number
  rate_limit: number
  enable_ai_agent?: boolean
  ai_max_iterations?: number  // 0 = unlimited
  ai_custom_prompt?: string
  ai_persona_id?: string | null  // AI 人格 ID
}

export interface ScanTask {
  id: string
  target: string
  scan_type: string
  status: 'PENDING' | 'RUNNING' | 'PAUSED' | 'COMPLETED' | 'FAILED' | 'CANCELLED'
  config: ScanConfig
  started_at: string | null
  completed_at: string | null
  created_at: string
  llm_summary: string | null
  llm_risk_score: number | null
  vulnerability_count: number
}

export interface Vulnerability {
  id: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  category: string | null
  description: string | null
  evidence: string | null
  location: string | null
  llm_analysis: string | null
  llm_remediation: string | null
  llm_false_positive_score: number | null
  created_at: string
}

// API functions
export async function getScans(params?: { skip?: number; limit?: number; status?: string }) {
  const { data } = await api.get<{ total: number; items: ScanTask[] }>('/scans', { params })
  return data
}

export async function getScan(scanId: string) {
  const { data } = await api.get<ScanTask>(`/scans/${scanId}`)
  return data
}

export async function createScan(target: string, scanType: string, config: Partial<ScanConfig>) {
  const { data } = await api.post<ScanTask>('/scans', {
    target,
    scan_type: scanType,
    config,
  })
  return data
}

export async function getVulnerabilities(scanId: string, params?: { skip?: number; limit?: number; severity?: string }) {
  const { data } = await api.get<{ total: number; items: Vulnerability[] }>(
    `/scans/${scanId}/vulnerabilities`,
    { params }
  )
  return data
}

export async function cancelScan(scanId: string) {
  const { data } = await api.post(`/scans/${scanId}/cancel`)
  return data
}

export async function deleteScan(scanId: string) {
  const { data } = await api.delete(`/scans/${scanId}`)
  return data
}

export interface ScanProgress {
  scan_id: string
  status: string
  phase: string | null
  message: string | null
}

export async function getScanProgress(scanId: string) {
  const { data } = await api.get<ScanProgress>(`/scans/${scanId}/progress`)
  return data
}

export interface ScanLogEntry {
  timestamp: string
  type: 'info' | 'tool' | 'output' | 'llm' | 'error' | 'success'
  message: string
  details: string | null
  tool: string | null
}

export interface ScanLogs {
  scan_id: string
  logs: ScanLogEntry[]
  next_index: number
}

export async function getScanLogs(scanId: string, sinceIndex: number = 0) {
  const { data } = await api.get<ScanLogs>(`/scans/${scanId}/logs`, {
    params: { since_index: sinceIndex }
  })
  return data
}

// ============ Scan Messages ============

export interface ScanMessage {
  id: string
  scan_task_id: string
  role: 'agent' | 'user'
  content: string
  is_processed: boolean
  created_at: string
}

export interface ScanMessageList {
  scan_id: string
  messages: ScanMessage[]
  is_paused: boolean
  pending_question: string | null
}

export async function getScanMessages(scanId: string) {
  const { data } = await api.get<ScanMessageList>(`/scans/${scanId}/messages`)
  return data
}

export async function sendScanMessage(scanId: string, content: string) {
  const { data } = await api.post<ScanMessage>(`/scans/${scanId}/messages`, { content })
  return data
}

// ============ Post-Scan Chat (分析对话) ============

export interface ChatMessage {
  id: string
  scan_id: string
  role: 'user' | 'assistant'
  content: string
  created_at: string
}

export interface ChatHistory {
  scan_id: string
  messages: ChatMessage[]
  can_chat: boolean
}

export async function getScanChatHistory(scanId: string) {
  const { data } = await api.get<ChatHistory>(`/scans/${scanId}/chat`)
  return data
}

export async function sendScanChatMessage(scanId: string, message: string) {
  const { data } = await api.post<ChatMessage>(`/scans/${scanId}/chat`, { message })
  return data
}

export async function getAvailableScanners() {
  const { data } = await api.get<{ available_scanners: string[] }>('/scanners')
  return data.available_scanners
}

// ============ Security Tools / Knowledgebase ============

export interface SecurityTool {
  id: string
  name: string
  description: string | null
  tool_type: 'script' | 'nuclei' | 'wordlist' | 'config' | 'skill'
  filename: string
  file_size: number | null
  category: string | null
  tags: string[]
  usage_instructions: string | null
  is_enabled: boolean
  is_verified: boolean
  author: string | null
  version: string | null
  created_at: string
  updated_at: string | null
}

export async function getTools(params?: { 
  skip?: number
  limit?: number
  tool_type?: string
  category?: string
  enabled_only?: boolean
}) {
  const { data } = await api.get<{ total: number; items: SecurityTool[] }>('/tools', { params })
  return data
}

export async function getTool(toolId: string) {
  const { data } = await api.get<SecurityTool>(`/tools/${toolId}`)
  return data
}

export async function getToolContent(toolId: string) {
  const { data } = await api.get<{ content: string; filename: string }>(`/tools/${toolId}/content`)
  return data
}

export async function uploadTool(formData: FormData) {
  const { data } = await api.post<SecurityTool>('/tools', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
  return data
}

export async function updateTool(toolId: string, updates: Partial<SecurityTool>) {
  const { data } = await api.patch<SecurityTool>(`/tools/${toolId}`, updates)
  return data
}

export async function deleteTool(toolId: string) {
  const { data } = await api.delete(`/tools/${toolId}`)
  return data
}

export async function getToolCategories() {
  const { data } = await api.get<{ categories: string[]; tool_types: string[] }>('/tools/categories/list')
  return data
}

// ============ LLM Settings ============

export interface LLMConfig {
  id: string
  name: string
  provider: string
  api_base_url: string | null
  has_api_key: boolean
  model: string
  temperature: number
  max_tokens: number
  is_active: boolean
  is_enabled: boolean
  priority: number
  total_requests: number
  failed_requests: number
  last_used_at: string | null
  last_error: string | null
  created_at: string
  updated_at: string | null
}

export interface LLMConfigCreate {
  name: string
  provider: string
  api_base_url?: string
  api_key?: string
  model: string
  temperature?: number
  max_tokens?: number
  is_active?: boolean
  priority?: number
}

export interface SearchSettings {
  enabled: boolean
  provider: string
  api_key: string | null
  max_results: number
}

export async function getLLMConfigs() {
  const { data } = await api.get<{ total: number; items: LLMConfig[] }>('/settings/llm')
  return data
}

export async function createLLMConfig(config: LLMConfigCreate) {
  const { data } = await api.post<LLMConfig>('/settings/llm', config)
  return data
}

export async function updateLLMConfig(id: string, updates: Partial<LLMConfigCreate & { is_enabled?: boolean }>) {
  const { data } = await api.patch<LLMConfig>(`/settings/llm/${id}`, updates)
  return data
}

export async function deleteLLMConfig(id: string) {
  const { data } = await api.delete(`/settings/llm/${id}`)
  return data
}

export async function activateLLMConfig(id: string) {
  const { data } = await api.post(`/settings/llm/${id}/activate`)
  return data
}

export async function testLLMConfig(id: string) {
  const { data } = await api.post<{ success: boolean; message: string; response?: string; error?: string }>(
    `/settings/llm/${id}/test`
  )
  return data
}

export async function getSearchSettings() {
  const { data } = await api.get<SearchSettings>('/settings/search')
  return data
}

export async function updateSearchSettings(settings: SearchSettings) {
  const { data } = await api.put<SearchSettings>('/settings/search', settings)
  return data
}

// ============ AI Personas ============

export interface AIPersona {
  id: string
  name: string
  description: string | null
  system_prompt: string
  is_default: boolean
  is_enabled: boolean
  created_at: string
  updated_at: string | null
}

export interface AIPersonaBrief {
  id: string
  name: string
  description: string | null
  is_default: boolean
}

export interface AIPersonaCreate {
  name: string
  description?: string | null
  system_prompt: string
  is_default?: boolean
}

export interface AIPersonaUpdate {
  name?: string
  description?: string | null
  system_prompt?: string
  is_default?: boolean
  is_enabled?: boolean
}

export async function getPersonas() {
  const { data } = await api.get<{ total: number; items: AIPersona[] }>('/settings/personas')
  return data
}

export async function getPersonasBrief() {
  const { data } = await api.get<AIPersonaBrief[]>('/settings/personas/brief')
  return data
}

export async function getPersona(id: string) {
  const { data } = await api.get<AIPersona>(`/settings/personas/${id}`)
  return data
}

export async function createPersona(persona: AIPersonaCreate) {
  const { data } = await api.post<AIPersona>('/settings/personas', persona)
  return data
}

export async function updatePersona(id: string, updates: AIPersonaUpdate) {
  const { data } = await api.patch<AIPersona>(`/settings/personas/${id}`, updates)
  return data
}

export async function deletePersona(id: string) {
  const { data } = await api.delete(`/settings/personas/${id}`)
  return data
}

export async function setDefaultPersona(id: string) {
  const { data } = await api.post(`/settings/personas/${id}/set-default`)
  return data
}
