import React, { useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
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
      <div className="auth-card">
        <h1>{isRegister ? '注册' : '登录'}</h1>
        <p className="auth-subtitle">
          {isRegister
            ? '创建一个新账户开始使用'
            : '登录到您的账户'}
        </p>

        {error && <div className="auth-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">用户名</label>
            <input
              id="username"
              type="text"
              name="username"
              value={formData.username}
              onChange={handleChange}
              placeholder="输入用户名"
              required
              minLength={3}
            />
          </div>

          {isRegister && (
            <div className="form-group">
              <label htmlFor="email">邮箱</label>
              <input
                id="email"
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="输入邮箱地址"
                required
              />
            </div>
          )}

          <div className="form-group">
            <label htmlFor="password">密码</label>
            <input
              id="password"
              type="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="输入密码"
              required
              minLength={8}
            />
          </div>

          {isRegister && (
            <div className="form-group">
              <label htmlFor="password_confirm">确认密码</label>
              <input
                id="password_confirm"
                type="password"
                name="password_confirm"
                value={formData.password_confirm}
                onChange={handleChange}
                placeholder="再次输入密码"
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

        <p className="auth-toggle">
          {isRegister ? '已有账户?' : '没有账户?'}
          {' '}
          <button type="button" onClick={toggleMode} className="toggle-link">
            {isRegister ? '登录' : '注册'}
          </button>
        </p>
      </div>
    </div>
  );
};

