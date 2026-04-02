import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { format } from 'date-fns'
import { Activity, AlertTriangle, CheckCircle, Clock, XCircle, Pause } from 'lucide-react'
import { getScans, ScanTask } from '../lib/api'
import SeverityBadge from '../components/SeverityBadge'

const statusIcons: Record<string, React.ComponentType<{ className?: string }>> = {
  PENDING: Clock,
  RUNNING: Activity,
  PAUSED: Pause,
  COMPLETED: CheckCircle,
  FAILED: XCircle,
  CANCELLED: XCircle,
}

const statusColors: Record<string, string> = {
  PENDING: 'text-yellow-500',
  RUNNING: 'text-blue-500',
  PAUSED: 'text-orange-500',
  COMPLETED: 'text-green-500',
  FAILED: 'text-red-500',
  CANCELLED: 'text-gray-500',
}

const statusLabels: Record<string, string> = {
  PENDING: '等待中',
  RUNNING: '扫描中',
  PAUSED: '等待回复',
  COMPLETED: '已完成',
  FAILED: '失败',
  CANCELLED: '已取消',
}

export default function Dashboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['scans'],
    queryFn: () => getScans({ limit: 20 }),
    refetchInterval: 5000,
  })

  if (isLoading) {
    return <div className="text-center py-12">加载中...</div>
  }

  if (error) {
    return (
      <div className="text-center py-12 text-red-500">
        加载失败: {(error as Error).message}
      </div>
    )
  }

  const scans = data?.items || []

  return (
    <div>
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">仪表盘</h1>
        <Link
          to="/new-scan"
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center gap-2"
        >
          新建扫描
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        <StatCard
          label="总扫描数"
          value={data?.total || 0}
          icon={Activity}
        />
        <StatCard
          label="进行中"
          value={scans.filter(s => s.status === 'RUNNING').length}
          icon={Clock}
          color="text-blue-500"
        />
        <StatCard
          label="已完成"
          value={scans.filter(s => s.status === 'COMPLETED').length}
          icon={CheckCircle}
          color="text-green-500"
        />
        <StatCard
          label="漏洞数"
          value={scans.reduce((sum, s) => sum + s.vulnerability_count, 0)}
          icon={AlertTriangle}
          color="text-orange-500"
        />
      </div>

      {/* Scan List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow">
        <table className="w-full">
          <thead className="bg-gray-100 dark:bg-gray-700">
            <tr>
              <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200">目标</th>
              <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200">类型</th>
              <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200">状态</th>
              <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200">漏洞</th>
              <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200">风险评分</th>
              <th className="px-4 py-3 text-left text-gray-700 dark:text-gray-200">创建时间</th>
            </tr>
          </thead>
          <tbody>
            {scans.map(scan => (
              <ScanRow key={scan.id} scan={scan} />
            ))}
          </tbody>
        </table>

        {scans.length === 0 && (
          <div className="text-center py-12 text-gray-500">
            暂无扫描记录，点击"新建扫描"开始
          </div>
        )}
      </div>
    </div>
  )
}

function StatCard({
  label,
  value,
  icon: Icon,
  color = 'text-gray-400',
}: {
  label: string
  value: number
  icon: React.ComponentType<{ className?: string }>
  color?: string
}) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg p-4 shadow">
      <div className="flex items-center gap-3">
        <Icon className={`w-8 h-8 ${color}`} />
        <div>
          <p className="text-2xl font-bold">{value}</p>
          <p className="text-sm text-gray-500 dark:text-gray-400">{label}</p>
        </div>
      </div>
    </div>
  )
}

function ScanRow({ scan }: { scan: ScanTask }) {
  const StatusIcon = statusIcons[scan.status] || Clock

  return (
    <tr className="border-t border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750">
      <td className="px-4 py-3">
        <Link
          to={`/scans/${scan.id}`}
          className="text-blue-600 dark:text-blue-400 hover:underline"
        >
          {scan.target}
        </Link>
      </td>
      <td className="px-4 py-3 capitalize">{scan.scan_type}</td>
      <td className="px-4 py-3">
        <span className={`flex items-center gap-2 ${statusColors[scan.status] || 'text-gray-500'}`}>
          <StatusIcon className="w-4 h-4" />
          {statusLabels[scan.status] || scan.status}
        </span>
      </td>
      <td className="px-4 py-3">{scan.vulnerability_count}</td>
      <td className="px-4 py-3">
        {scan.llm_risk_score !== null ? (
          <RiskScore score={scan.llm_risk_score} />
        ) : (
          '-'
        )}
      </td>
      <td className="px-4 py-3 text-gray-500 dark:text-gray-400">
        {format(new Date(scan.created_at), 'MM-dd HH:mm')}
      </td>
    </tr>
  )
}

function RiskScore({ score }: { score: number }) {
  const color =
    score >= 80 ? 'text-red-500' :
    score >= 60 ? 'text-orange-500' :
    score >= 40 ? 'text-yellow-500' :
    'text-green-500'

  return <span className={`font-semibold ${color}`}>{score}/100</span>
}
