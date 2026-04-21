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
          throw new Error('Passwords do not match');
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
      setError(err instanceof Error ? err.message : 'An error occurred');
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
        <h1>{isRegister ? 'Register' : 'Login'}</h1>
        <p className="auth-subtitle">
          {isRegister
            ? 'Create a new account to get started'
            : 'Sign in to your account'}
        </p>

        {error && <div className="auth-error">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              name="username"
              value={formData.username}
              onChange={handleChange}
              placeholder="Enter your username"
              required
              minLength={3}
            />
          </div>

          {isRegister && (
            <div className="form-group">
              <label htmlFor="email">Email</label>
              <input
                id="email"
                type="email"
                name="email"
                value={formData.email}
                onChange={handleChange}
                placeholder="Enter your email"
                required
              />
            </div>
          )}

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              id="password"
              type="password"
              name="password"
              value={formData.password}
              onChange={handleChange}
              placeholder="Enter your password"
              required
              minLength={8}
            />
          </div>

          {isRegister && (
            <div className="form-group">
              <label htmlFor="password_confirm">Confirm Password</label>
              <input
                id="password_confirm"
                type="password"
                name="password_confirm"
                value={formData.password_confirm}
                onChange={handleChange}
                placeholder="Confirm your password"
                required
                minLength={8}
              />
            </div>
          )}

          <button type="submit" disabled={isLoading} className="auth-submit">
            {isLoading
              ? 'Loading...'
              : isRegister
              ? 'Register'
              : 'Login'}
          </button>
        </form>

        <p className="auth-toggle">
          {isRegister ? 'Already have an account?' : 'Don\'t have an account?'}
          {' '}
          <button type="button" onClick={toggleMode} className="toggle-link">
            {isRegister ? 'Login' : 'Register'}
          </button>
        </p>
      </div>
    </div>
  );
};
