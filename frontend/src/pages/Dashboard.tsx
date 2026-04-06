import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { format, parseISO, startOfDay } from 'date-fns'
import { Activity, AlertTriangle, CheckCircle, Clock, XCircle, Pause, PieChart as PieChartIcon, TrendingUp } from 'lucide-react'
import {
  PieChart,
  Pie,
  Cell,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from 'recharts'
import { getScans, ScanTask } from '../lib/api'

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

// Chart color constants
const chartStatusColors: Record<string, string> = {
  PENDING: '#EAB308',
  RUNNING: '#3B82F6',
  PAUSED: '#F97316',
  COMPLETED: '#22C55E',
  FAILED: '#EF4444',
  CANCELLED: '#6B7280',
}

const severityColors: Record<string, string> = {
  critical: '#DC2626',
  high: '#F97316',
  medium: '#EAB308',
  low: '#3B82F6',
  info: '#6B7280',
}

const severityLabels: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

export default function Dashboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['scans'],
    queryFn: () => getScans({ limit: 100 }),
    refetchInterval: 5000,
  })

  // Compute chart data
  const { statusData, severityData, trendData, scanTypeData } = useMemo(() => {
    const scans = data?.items || []

    // Task status distribution
    const statusCount: Record<string, number> = {}
    scans.forEach(scan => {
      statusCount[scan.status] = (statusCount[scan.status] || 0) + 1
    })
    const statusData = Object.entries(statusCount).map(([status, count]) => ({
      name: statusLabels[status] || status,
      value: count,
      color: chartStatusColors[status] || '#6B7280',
    }))

    // Vulnerability severity distribution (simulated from risk scores and counts)
    const severityCount: Record<string, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    }
    scans.forEach(scan => {
      if (scan.vulnerability_count > 0) {
        const score = scan.llm_risk_score || 50
        if (score >= 80) severityCount.critical += Math.ceil(scan.vulnerability_count * 0.3)
        else if (score >= 60) severityCount.high += Math.ceil(scan.vulnerability_count * 0.3)
        else if (score >= 40) severityCount.medium += Math.ceil(scan.vulnerability_count * 0.3)
        else if (score >= 20) severityCount.low += Math.ceil(scan.vulnerability_count * 0.3)
        else severityCount.info += scan.vulnerability_count
      }
    })
    const severityData = Object.entries(severityCount)
      .filter(([, count]) => count > 0)
      .map(([severity, count]) => ({
        name: severityLabels[severity] || severity,
        value: count,
        color: severityColors[severity],
      }))

    // Vulnerability trend by date
    const trendMap: Record<string, number> = {}
    scans.forEach(scan => {
      const day = format(startOfDay(parseISO(scan.created_at)), 'MM-dd')
      trendMap[day] = (trendMap[day] || 0) + scan.vulnerability_count
    })
    const trendData = Object.entries(trendMap)
      .sort(([a], [b]) => a.localeCompare(b))
      .slice(-14) // Last 14 days
      .map(([date, count]) => ({ date, vulnerabilities: count }))

    // Scan type distribution
    const typeCount: Record<string, number> = {}
    scans.forEach(scan => {
      typeCount[scan.scan_type] = (typeCount[scan.scan_type] || 0) + 1
    })
    const typeColors = ['#3B82F6', '#22C55E', '#EAB308', '#F97316', '#8B5CF6', '#EC4899']
    const scanTypeData = Object.entries(typeCount).map(([type, count], index) => ({
      name: type,
      value: count,
      color: typeColors[index % typeColors.length],
    }))

    return { statusData, severityData, trendData, scanTypeData }
  }, [data])

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
  const recentScans = scans.slice(0, 10)
  const totalVulnerabilities = scans.reduce((sum, s) => sum + s.vulnerability_count, 0)

  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:justify-between sm:items-center gap-3 mb-6">
        <h1 className="text-2xl font-bold">仪表盘</h1>
        <Link
          to="/new-scan"
          className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center gap-2"
        >
          新建扫描
        </Link>
      </div>

      {/* Stats + Task Status Pie */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-6">
        {/* Stats Cards */}
        <div className="lg:col-span-2 grid grid-cols-2 md:grid-cols-4 gap-4">
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
            value={totalVulnerabilities}
            icon={AlertTriangle}
            color="text-orange-500"
          />
        </div>

        {/* Task Status Pie Chart */}
        <ChartCard title="任务状态分布" icon={PieChartIcon}>
          {statusData.length > 0 ? (
            <ResponsiveContainer width="100%" height={180}>
              <PieChart>
                <Pie
                  data={statusData}
                  cx="50%"
                  cy="50%"
                  innerRadius={40}
                  outerRadius={70}
                  paddingAngle={2}
                  dataKey="value"
                  label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                  labelLine={false}
                >
                  {statusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'rgba(31, 41, 55, 0.9)',
                    border: 'none',
                    borderRadius: '8px',
                    color: '#fff',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <EmptyChartState message="暂无任务数据" />
          )}
        </ChartCard>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
        {/* Vulnerability Trend */}
        <ChartCard title="漏洞趋势" icon={TrendingUp} className="lg:col-span-1">
          {trendData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={trendData} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis
                  dataKey="date"
                  stroke="#9CA3AF"
                  fontSize={12}
                  tickLine={false}
                />
                <YAxis
                  stroke="#9CA3AF"
                  fontSize={12}
                  tickLine={false}
                  allowDecimals={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: 'rgba(31, 41, 55, 0.9)',
                    border: 'none',
                    borderRadius: '8px',
                    color: '#fff',
                  }}
                  formatter={(value: number) => [value, '漏洞数']}
                />
                <Line
                  type="monotone"
                  dataKey="vulnerabilities"
                  stroke="#F97316"
                  strokeWidth={2}
                  dot={{ fill: '#F97316', strokeWidth: 2, r: 4 }}
                  activeDot={{ r: 6 }}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <EmptyChartState message="暂无趋势数据" />
          )}
        </ChartCard>

        {/* Severity Distribution + Scan Type */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Severity Distribution */}
          <ChartCard title="漏洞等级分布" icon={AlertTriangle}>
            {severityData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie
                    data={severityData}
                    cx="50%"
                    cy="50%"
                    innerRadius={35}
                    outerRadius={60}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {severityData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(31, 41, 55, 0.9)',
                      border: 'none',
                      borderRadius: '8px',
                      color: '#fff',
                    }}
                  />
                  <Legend
                    verticalAlign="bottom"
                    height={36}
                    formatter={(value) => <span className="text-gray-400 text-xs">{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <EmptyChartState message="暂无漏洞数据" />
            )}
          </ChartCard>

          {/* Scan Type Distribution */}
          <ChartCard title="扫描类型分布" icon={PieChartIcon}>
            {scanTypeData.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <PieChart>
                  <Pie
                    data={scanTypeData}
                    cx="50%"
                    cy="50%"
                    innerRadius={35}
                    outerRadius={60}
                    paddingAngle={2}
                    dataKey="value"
                  >
                    {scanTypeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: 'rgba(31, 41, 55, 0.9)',
                      border: 'none',
                      borderRadius: '8px',
                      color: '#fff',
                    }}
                  />
                  <Legend
                    verticalAlign="bottom"
                    height={36}
                    formatter={(value) => <span className="text-gray-400 text-xs">{value}</span>}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <EmptyChartState message="暂无扫描数据" />
            )}
          </ChartCard>
        </div>
      </div>

      {/* Recent Scan List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg overflow-hidden shadow">
        <div className="px-4 py-3 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
          <h3 className="font-semibold text-gray-700 dark:text-gray-200">最近扫描任务</h3>
          <Link to="/scans" className="text-sm text-blue-500 hover:text-blue-400">
            查看全部 →
          </Link>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px]">
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
              {recentScans.map(scan => (
                <ScanRow key={scan.id} scan={scan} />
              ))}
            </tbody>
          </table>
        </div>

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

function ChartCard({
  title,
  icon: Icon,
  children,
  className = '',
}: {
  title: string
  icon: React.ComponentType<{ className?: string }>
  children: React.ReactNode
  className?: string
}) {
  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg p-4 shadow ${className}`}>
      <div className="flex items-center gap-2 mb-3">
        <Icon className="w-5 h-5 text-gray-400" />
        <h3 className="font-semibold text-gray-700 dark:text-gray-200">{title}</h3>
      </div>
      {children}
    </div>
  )
}

function EmptyChartState({ message }: { message: string }) {
  return (
    <div className="flex items-center justify-center h-[180px] text-gray-400">
      <div className="text-center">
        <PieChartIcon className="w-12 h-12 mx-auto mb-2 opacity-30" />
        <p className="text-sm">{message}</p>
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
