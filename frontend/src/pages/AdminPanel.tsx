import React, { useEffect, useState } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../lib/api';
import '../styles/AdminPanel.css';

interface User {
  id: string;
  username: string;
  email: string;
  role: 'user' | 'admin';
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export const AdminPanel: React.FC = () => {
  const { isAdmin } = useAuth();
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editForm, setEditForm] = useState<Partial<User>>({});

  if (!isAdmin) {
    return <div className="admin-panel-error">Access denied. Admin only.</div>;
  }

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const response = await api.get('/admin/users?limit=100');
      setUsers(response.data.items);
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (user: User) => {
    setEditingId(user.id);
    setEditForm(user);
  };

  const handleSaveEdit = async () => {
    if (!editingId) return;

    try {
      await api.patch(`/admin/users/${editingId}`, editForm);
      setEditingId(null);
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to update user');
    }
  };

  const handleDelete = async (userId: string) => {
    if (!window.confirm('Are you sure you want to delete this user?')) return;

    try {
      await api.delete(`/admin/users/${userId}`);
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete user');
    }
  };

  const handleToggleActive = async (user: User) => {
    try {
      await api.patch(`/admin/users/${user.id}`, {
        is_active: !user.is_active
      });
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to toggle user status');
    }
  };

  return (
    <div className="admin-panel">
      <h1>User Management</h1>

      {error && <div className="admin-error">{error}</div>}

      {loading ? (
        <div className="admin-loading">Loading...</div>
      ) : (
        <div className="users-table-container">
          <table className="users-table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Last Login</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((user) => (
                <tr key={user.id} className={editingId === user.id ? 'editing' : ''}>
                  <td>
                    {editingId === user.id ? (
                      <input
                        type="text"
                        value={editForm.username || ''}
                        onChange={(e) =>
                          setEditForm({ ...editForm, username: e.target.value })
                        }
                      />
                    ) : (
                      user.username
                    )}
                  </td>
                  <td>
                    {editingId === user.id ? (
                      <input
                        type="email"
                        value={editForm.email || ''}
                        onChange={(e) =>
                          setEditForm({ ...editForm, email: e.target.value })
                        }
                      />
                    ) : (
                      user.email
                    )}
                  </td>
                  <td>
                    {editingId === user.id ? (
                      <select
                        value={editForm.role || 'user'}
                        onChange={(e) =>
                          setEditForm({
                            ...editForm,
                            role: e.target.value as 'user' | 'admin',
                          })
                        }
                      >
                        <option value="user">User</option>
                        <option value="admin">Admin</option>
                      </select>
                    ) : (
                      <span className={`role-badge role-${user.role}`}>
                        {user.role}
                      </span>
                    )}
                  </td>
                  <td>
                    <button
                      className={`status-badge ${
                        user.is_active ? 'active' : 'inactive'
                      }`}
                      onClick={() => handleToggleActive(user)}
                    >
                      {user.is_active ? 'Active' : 'Inactive'}
                    </button>
                  </td>
                  <td>
                    {user.last_login_at
                      ? new Date(user.last_login_at).toLocaleDateString()
                      : 'Never'}
                  </td>
                  <td className="actions-cell">
                    {editingId === user.id ? (
                      <>
                        <button
                          className="btn-save"
                          onClick={handleSaveEdit}
                        >
                          Save
                        </button>
                        <button
                          className="btn-cancel"
                          onClick={() => setEditingId(null)}
                        >
                          Cancel
                        </button>
                      </>
                    ) : (
                      <>
                        <button
                          className="btn-edit"
                          onClick={() => handleEdit(user)}
                        >
                          Edit
                        </button>
                        <button
                          className="btn-delete"
                          onClick={() => handleDelete(user.id)}
                        >
                          Delete
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="admin-stats">
        <div className="stat">
          <label>Total Users</label>
          <span>{users.length}</span>
        </div>
        <div className="stat">
          <label>Admins</label>
          <span>{users.filter((u) => u.role === 'admin').length}</span>
        </div>
        <div className="stat">
          <label>Active</label>
          <span>{users.filter((u) => u.is_active).length}</span>
        </div>
      </div>
    </div>
  );
};
