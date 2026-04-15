import { useState } from 'react'
import { Outlet, Link, useLocation } from 'react-router-dom'
import { Shield, LayoutDashboard, Plus, Database, Sun, Moon, Monitor, Bot, Settings, List, Menu, X } from 'lucide-react'
import clsx from 'clsx'
import { useTheme } from '../contexts/ThemeContext'

const navItems = [
  { to: '/', label: '仪表盘', icon: LayoutDashboard },
  { to: '/scans', label: '扫描历史', icon: List },
  { to: '/knowledgebase', label: '知识库', icon: Database },
  { to: '/personas', label: 'AI 人格', icon: Bot },
]

export default function Layout() {
  const location = useLocation()
  const { theme, setTheme } = useTheme()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 text-gray-900 dark:text-gray-100 transition-colors">
      <header className="md:hidden sticky top-0 z-30 bg-white/95 dark:bg-gray-800/95 backdrop-blur border-b border-gray-200 dark:border-gray-700">
        <div className="h-14 px-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-500" />
            <span className="text-lg font-bold">Shelling</span>
          </div>
          <button
            type="button"
            onClick={() => setMobileMenuOpen(true)}
            className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
            aria-label="打开菜单"
          >
            <Menu className="w-5 h-5" />
          </button>
        </div>
      </header>

      {mobileMenuOpen && (
        <div className="md:hidden fixed inset-0 z-50">
          <button
            type="button"
            className="absolute inset-0 bg-black/40"
            onClick={() => setMobileMenuOpen(false)}
            aria-label="关闭菜单遮罩"
          />
          <aside className="relative w-72 max-w-[85vw] h-full bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 flex flex-col">
            <div className="p-4 flex items-center justify-between border-b border-gray-200 dark:border-gray-700 gap-2">
              <div className="flex items-center gap-2 flex-1 min-w-0">
                <Shield className="w-7 h-7 text-blue-500 flex-shrink-0" />
                <span className="text-xl font-bold truncate">Shelling</span>
              </div>
              {/* Theme Switcher - Mobile */}
              <div className="flex gap-1 bg-gray-100 dark:bg-gray-700 rounded-lg p-1 flex-shrink-0">
                <button
                  onClick={() => setTheme('light')}
                  className={clsx(
                    'p-1.5 rounded text-sm transition-colors',
                    theme === 'light'
                      ? 'bg-white dark:bg-gray-600 shadow text-gray-900 dark:text-white'
                      : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                  )}
                  title="明亮模式"
                >
                  <Sun className="w-3 h-3" />
                </button>
                <button
                  onClick={() => setTheme('dark')}
                  className={clsx(
                    'p-1.5 rounded text-sm transition-colors',
                    theme === 'dark'
                      ? 'bg-white dark:bg-gray-600 shadow text-gray-900 dark:text-white'
                      : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                  )}
                  title="暗色模式"
                >
                  <Moon className="w-3 h-3" />
                </button>
                <button
                  onClick={() => setTheme('system')}
                  className={clsx(
                    'p-1.5 rounded text-sm transition-colors',
                    theme === 'system'
                      ? 'bg-white dark:bg-gray-600 shadow text-gray-900 dark:text-white'
                      : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
                  )}
                  title="跟随系统"
                >
                  <Monitor className="w-3 h-3" />
                </button>
              </div>
              <button
                type="button"
                onClick={() => setMobileMenuOpen(false)}
                className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 flex-shrink-0"
                aria-label="关闭菜单"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

        <div className="px-4 py-2">
          <Link
            to="/new-scan"
            onClick={() => setMobileMenuOpen(false)}
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-medium"
          >
            <Plus className="w-5 h-5" />
            新建扫描
          </Link>
        </div>

        <nav className="px-4 py-2 space-y-2 flex-1">
              {navItems.map(item => (
                <Link
                  key={`mobile-${item.to}`}
                  to={item.to}
                  onClick={() => setMobileMenuOpen(false)}
                  className={clsx(
                    'flex items-center gap-3 px-4 py-2 rounded-lg transition-colors',
                    location.pathname === item.to
                      ? 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white'
                      : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                  )}
                >
                  <item.icon className="w-5 h-5" />
                  {item.label}
                </Link>
              ))}
            </nav>

            <div className="p-4 border-t border-gray-200 dark:border-gray-700 mt-auto">
              <Link
                to="/settings"
                onClick={() => setMobileMenuOpen(false)}
                className={clsx(
                  'flex items-center gap-3 px-4 py-2 rounded-lg transition-colors',
                  location.pathname === '/settings'
                    ? 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white'
                    : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
                )}
              >
                <Settings className="w-5 h-5" />
                系统设置
              </Link>
            </div>
          </aside>
        </div>
      )}

      <div className="flex min-h-[calc(100vh-3.5rem)] md:min-h-screen">
        {/* Sidebar */}
        <aside className="hidden md:flex md:w-64 md:flex-col md:bg-white md:dark:bg-gray-800 md:border-r md:border-gray-200 md:dark:border-gray-700 md:sticky md:top-0 md:h-screen">
        <div className="p-4 flex items-center justify-between border-b border-gray-200 dark:border-gray-700 gap-2">
          <div className="flex items-center gap-2 flex-1 min-w-0">
            <Shield className="w-8 h-8 text-blue-500 flex-shrink-0" />
            <span className="text-xl font-bold truncate">Shelling</span>
          </div>
          {/* Theme Switcher - Desktop */}
          <div className="flex gap-1 bg-gray-100 dark:bg-gray-700 rounded-lg p-1 flex-shrink-0">
            <button
              onClick={() => setTheme('light')}
              className={clsx(
                'p-1.5 rounded text-sm transition-colors',
                theme === 'light'
                  ? 'bg-white dark:bg-gray-600 shadow text-gray-900 dark:text-white'
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              )}
              title="明亮模式"
            >
              <Sun className="w-3 h-3" />
            </button>
            <button
              onClick={() => setTheme('dark')}
              className={clsx(
                'p-1.5 rounded text-sm transition-colors',
                theme === 'dark'
                  ? 'bg-white dark:bg-gray-600 shadow text-gray-900 dark:text-white'
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              )}
              title="暗色模式"
            >
              <Moon className="w-3 h-3" />
            </button>
            <button
              onClick={() => setTheme('system')}
              className={clsx(
                'p-1.5 rounded text-sm transition-colors',
                theme === 'system'
                  ? 'bg-white dark:bg-gray-600 shadow text-gray-900 dark:text-white'
                  : 'text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              )}
              title="跟随系统"
            >
              <Monitor className="w-3 h-3" />
            </button>
          </div>
        </div>

        <div className="px-4 py-2">
          <Link
            to="/new-scan"
            className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-medium"
          >
            <Plus className="w-5 h-5" />
            新建扫描
          </Link>
        </div>

        <nav className="px-4 py-2 space-y-2 flex-1">
          {navItems.map(item => (
            <Link
              key={item.to}
              to={item.to}
              className={clsx(
                'flex items-center gap-3 px-4 py-2 rounded-lg transition-colors',
                location.pathname === item.to
                  ? 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white'
                  : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
              )}
            >
              <item.icon className="w-5 h-5" />
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="p-4 border-t border-gray-200 dark:border-gray-700">
          <Link
            to="/settings"
            className={clsx(
              'flex items-center gap-3 px-4 py-2 rounded-lg transition-colors',
              location.pathname === '/settings'
                ? 'bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white'
                : 'text-gray-600 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700'
            )}
          >
            <Settings className="w-5 h-5" />
            系统设置
          </Link>
        </div>
        </aside>

        {/* Main content */}
        <main className="flex-1 p-4 sm:p-6 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
