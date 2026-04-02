import { Outlet, Link, useLocation } from 'react-router-dom'
import { Shield, LayoutDashboard, Plus, Database, Sun, Moon, Monitor, Bot, Settings } from 'lucide-react'
import clsx from 'clsx'
import { useTheme } from '../contexts/ThemeContext'

const navItems = [
  { to: '/', label: '仪表盘', icon: LayoutDashboard },
  { to: '/new-scan', label: '新建扫描', icon: Plus },
  { to: '/knowledgebase', label: '知识库', icon: Database },
  { to: '/personas', label: 'AI 人格', icon: Bot },
  { to: '/settings', label: '系统设置', icon: Settings },
]

export default function Layout() {
  const location = useLocation()
  const { theme, setTheme } = useTheme()

  return (
    <div className="min-h-screen flex bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 transition-colors">
      {/* Sidebar */}
      <aside className="w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700">
        <div className="p-4 flex items-center gap-2 border-b border-gray-200 dark:border-gray-700">
          <Shield className="w-8 h-8 text-blue-500" />
          <span className="text-xl font-bold">Shelling</span>
        </div>

        <nav className="p-4 space-y-2">
          {navItems.map(item => (
            <Link
              key={item.to}
              to={item.to}
              className={clsx(
                'flex items-center gap-3 px-4 py-2 rounded-lg transition-colors',
                location.pathname === item.to
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
              )}
            >
              <item.icon className="w-5 h-5" />
              {item.label}
            </Link>
          ))}
        </nav>

        {/* Theme Switcher */}
        <div className="absolute bottom-0 left-0 w-64 p-4 border-t border-gray-200 dark:border-gray-700">
          <p className="text-xs text-gray-500 dark:text-gray-400 mb-2">主题设置</p>
          <div className="flex gap-1 bg-gray-100 dark:bg-gray-700 rounded-lg p-1">
            <button
              onClick={() => setTheme('light')}
              className={clsx(
                'flex-1 flex items-center justify-center gap-1 py-1.5 rounded text-sm transition-colors',
                theme === 'light'
                  ? 'bg-white dark:bg-gray-600 shadow text-gray-900 dark:text-white'
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              )}
              title="明亮模式"
            >
              <Sun className="w-4 h-4" />
            </button>
            <button
              onClick={() => setTheme('dark')}
              className={clsx(
                'flex-1 flex items-center justify-center gap-1 py-1.5 rounded text-sm transition-colors',
                theme === 'dark'
                  ? 'bg-white dark:bg-gray-600 shadow text-gray-900 dark:text-white'
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              )}
              title="暗色模式"
            >
              <Moon className="w-4 h-4" />
            </button>
            <button
              onClick={() => setTheme('system')}
              className={clsx(
                'flex-1 flex items-center justify-center gap-1 py-1.5 rounded text-sm transition-colors',
                theme === 'system'
                  ? 'bg-white dark:bg-gray-600 shadow text-gray-900 dark:text-white'
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              )}
              title="跟随系统"
            >
              <Monitor className="w-4 h-4" />
            </button>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 p-6 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}
