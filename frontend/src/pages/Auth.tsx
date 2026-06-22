import React, { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { Shield } from 'lucide-react';
import '../styles/Auth.css';

export const Auth: React.FC = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { login, register } = useAuth();

  const isRegister = searchParams.get('mode') === 'register';
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    password_confirm: '',
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({ ...prev, [name]: value }));
    setError(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);

    try {
      if (isRegister) {
        if (formData.password !== formData.password_confirm) {
          throw new Error('密码不匹配');
        }
        await register(
          formData.username,
          formData.email,
          formData.password,
          formData.password_confirm
        );
      } else {
        await login(formData.username, formData.password);
      }
      navigate('/');
    } catch (err) {
      setError(err instanceof Error ? err.message : '发生错误');
    } finally {
      setIsLoading(false);
    }
  };

  const toggleMode = () => {
    const newMode = isRegister ? '' : 'register';
    navigate(newMode ? `?mode=${newMode}` : '/auth');
  };

  return (
    <div className="auth-container">
      {/* Left side - Brand info */}
      <div className="auth-brand">
        <div className="brand-content">
          <div className="brand-logo">
            <Shield className="w-16 h-16" />
          </div>
          <h1 className="brand-title">hack-scan</h1>
          <p className="brand-description">
            {isRegister 
              ? '加入 hack-scan，开始进行安全扫描和漏洞分析'
              : '使用 hack-scan 进行专业的安全扫描和漏洞评估'}
          </p>
        </div>
      </div>

      {/* Right side - Form */}
      <div className="auth-form-container">
        <div className="auth-card">
          <h2>{isRegister ? '注册' : '登录'}</h2>

          {error && <div className="auth-error">{error}</div>}

          <form onSubmit={handleSubmit}>
            <div className="form-group">
              <input
                id="username"
                type="text"
                name="username"
                value={formData.username}
                onChange={handleChange}
                placeholder={isRegister ? "创建用户名" : "用户名或邮箱"}
                required
                minLength={3}
              />
            </div>

            {isRegister && (
              <div className="form-group">
                <input
                  id="email"
                  type="email"
                  name="email"
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="邮箱地址"
                  required
                />
              </div>
            )}

            <div className="form-group">
              <input
                id="password"
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                placeholder="密码"
                required
                minLength={8}
              />
            </div>

            {isRegister && (
              <div className="form-group">
                <input
                  id="password_confirm"
                  type="password"
                  name="password_confirm"
                  value={formData.password_confirm}
                  onChange={handleChange}
                  placeholder="确认密码"
                  required
                  minLength={8}
                />
              </div>
            )}

            <button type="submit" disabled={isLoading} className="auth-submit">
              {isLoading
                ? '加载中...'
                : isRegister
                ? '注册'
                : '登录'}
            </button>
          </form>

          {!isRegister && (
            <div className="auth-forgot">
              <a href="#forgot" onClick={(e) => {
                e.preventDefault();
                alert('请联系管理员重置密码');
              }}>
                忘记密码？
              </a>
            </div>
          )}

          <div className="auth-divider"></div>

          <button 
            type="button" 
            onClick={toggleMode} 
            className={`auth-toggle-btn ${isRegister ? 'login-btn' : 'register-btn'}`}
          >
            {isRegister ? '已有账户？登录' : '创建新账户'}
          </button>
        </div>
      </div>
    </div>
  );
};

