import { useState, useCallback, useEffect } from 'react'
import { useDropzone } from 'react-dropzone'
import './App.css'
import Statistics from './components/Statistics'
import EditHomework from './components/EditHomework'

enum LLMProvider {
  DEEPSEEK = 'deepseek',
  DOUBAO = 'doubao'
}

interface ProcessedResult {
  content: string
  subject: string
  course: string
  dueDate: string
  dueDateConfidence?: number
  dueDateOriginal?: string
  confidence?: number
  suggestions?: string[]
  processedAt?: string
  provider?: string
  id?: string
  status: string
  isCompleted: boolean
  completedAt: string | null
  score: number | null
  difficulty: string
  timeSpent: number | null
  category: string
  createdAt: string
  updatedAt: string
}

interface ApiResponse {
  success: boolean
  data?: ProcessedResult
  error?: string
  details?: any
  message: string
}

interface User {
  _id: string
  username: string
  isAdmin: boolean
  status: string
  apiKeys: {
    [key in LLMProvider]: string
  }
  createdAt: string
  lastLoginAt: string | null
  homeworkCount?: number
}

interface AuthResponse {
  token: string
  user: User
  message?: string
}

// 添加API基础URL常量
const API_BASE_URL = 'http://localhost:3000';

// 添加导航页面枚举
enum Page {
  INPUT = 'input',
  VIEW = 'view',
  MANAGE = 'manage',
  STATISTICS = 'statistics'
}

function App() {
  const [text, setText] = useState('')
  const [files, setFiles] = useState<File[]>([])
  const [processing, setProcessing] = useState(false)
  const [processingMethod, setProcessingMethod] = useState<'nlp' | 'api'>('nlp')
  const [apiKey, setApiKey] = useState('')
  const [showApiKeyInput, setShowApiKeyInput] = useState(false)
  const [result, setResult] = useState<ProcessedResult | null>(null)
  const [isEditing, setIsEditing] = useState(false)
  const [isLoggedIn, setIsLoggedIn] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [llmProvider, setLLMProvider] = useState<LLMProvider>(LLMProvider.DEEPSEEK)
  const [user, setUser] = useState<User | null>(null)
  const [showLoginForm, setShowLoginForm] = useState(false)
  const [showRegisterForm, setShowRegisterForm] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [results, setResults] = useState<ProcessedResult[]>([])
  const [currentPage, setCurrentPage] = useState<Page>(Page.INPUT)
  const [users, setUsers] = useState<User[]>([])
  const [editingHomework, setEditingHomework] = useState<ProcessedResult | null>(null)

  // 检查登录状态
  useEffect(() => {
    const token = localStorage.getItem('token')
    const savedUser = localStorage.getItem('user')
    if (token && savedUser) {
      setIsLoggedIn(true)
      setUser(JSON.parse(savedUser))
    }
  }, [])

  // 获取历史记录
  useEffect(() => {
    if (isLoggedIn) {
      fetchResults()
    }
  }, [isLoggedIn])

  const fetchResults = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/results`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.success && Array.isArray(data.data)) {
          console.log('获取到的原始数据:', data.data);
          setResults(data.data);
          console.log('设置到state的数据:', data.data);
        } else {
          throw new Error(data.message || '获取历史记录失败');
        }
      } else {
        throw new Error('获取历史记录失败');
      }
    } catch (error) {
      console.error('获取历史记录失败:', error);
      setErrorMessage(error instanceof Error ? error.message : '获取历史记录失败，请重试');
    }
  };

  const handleLogin = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      })

      const data: AuthResponse = await response.json()
      
      if (response.ok) {
        localStorage.setItem('token', data.token)
        localStorage.setItem('user', JSON.stringify(data.user))
        setUser(data.user)
        setIsLoggedIn(true)
        setShowLoginForm(false)
        setUsername('')
        setPassword('')
        setErrorMessage(null)
        // 登录成功后立即获取历史记录
        await fetchResults()
      } else {
        setErrorMessage(data.message || '登录失败')
      }
    } catch (error) {
      setErrorMessage('登录失败，请重试')
    }
  }

  const handleRegister = async () => {
    try {
      console.log('发送注册请求:', { username, password });
      const response = await fetch(`${API_BASE_URL}/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      });

      const data = await response.json();
      console.log('注册响应:', data);
      
      if (response.ok) {
        setShowRegisterForm(false);
        setShowLoginForm(true);
        setUsername('');
        setPassword('');
        setErrorMessage('注册成功，请登录');
      } else {
        setErrorMessage(data.message || '注册失败，请重试');
        console.error('注册失败:', data);
      }
    } catch (error) {
      console.error('注册请求错误:', error);
      setErrorMessage('注册失败，请检查网络连接');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    setUser(null)
    setIsLoggedIn(false)
    setResults([])
  }

  const updateApiKey = async (provider: LLMProvider, newApiKey: string) => {
    try {
      // 先更新本地状态，提供即时反馈
      setUser(prev => {
        if (!prev) return null;
        return {
          ...prev,
          apiKeys: {
            ...prev.apiKeys,
            [provider]: newApiKey
          }
        };
      });

      const response = await fetch(`${API_BASE_URL}/user/api-keys`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ provider, apiKey: newApiKey })
      });

      const data = await response.json();
      
      if (data.success) {
        // 更新本地存储
        const savedUser = localStorage.getItem('user');
        if (savedUser) {
          const parsedUser = JSON.parse(savedUser);
          parsedUser.apiKeys = {
            ...parsedUser.apiKeys,
            [provider]: newApiKey
          };
          localStorage.setItem('user', JSON.stringify(parsedUser));
        }
        setErrorMessage('API密钥更新成功');
      } else {
        // 如果更新失败，回滚本地状态
        setUser(prev => {
          if (!prev) return null;
          const savedUser = localStorage.getItem('user');
          if (savedUser) {
            return JSON.parse(savedUser);
          }
          return prev;
        });
        throw new Error(data.message || 'API密钥更新失败');
      }
    } catch (error) {
      console.error('更新API密钥错误:', error);
      setErrorMessage(error instanceof Error ? error.message : 'API密钥更新失败，请重试');
    }
  };

  const onDrop = useCallback((acceptedFiles: File[]) => {
    setFiles(acceptedFiles)
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({ 
    onDrop,
    accept: {
      'image/*': ['.png', '.jpg', '.jpeg']
    },
    maxFiles: 1
  })

  const handleProcessingMethodChange = (method: 'nlp' | 'api') => {
    setProcessingMethod(method)
    setShowApiKeyInput(method === 'api' && !isLoggedIn)
  }

  const getProviderDisplayName = (provider: LLMProvider) => {
    switch (provider) {
      case LLMProvider.DEEPSEEK:
        return 'Deepseek';
      case LLMProvider.DOUBAO:
        return '豆包AI';
      default:
        return provider;
    }
  };

  // 检查令牌是否过期
  const checkTokenExpiration = () => {
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        const { exp } = JSON.parse(jsonPayload);
        if (exp * 1000 < Date.now()) {
          // 令牌已过期，清除登录状态
          handleLogout();
          setErrorMessage('登录已过期，请重新登录');
          return false;
        }
        return true;
      } catch (error) {
        console.error('令牌解析错误:', error);
        handleLogout();
        return false;
      }
    }
    return false;
  };

  const handleSubmit = async () => {
    if (!text && files.length === 0) return;
    if (processingMethod === 'api' && !isLoggedIn) {
      setErrorMessage('请先登录');
      return;
    }
    
    // 检查令牌是否过期
    if (!checkTokenExpiration()) {
      return;
    }
    
    setProcessing(true);
    setErrorMessage(null);
    try {
      const formData = new FormData();
      if (text) {
        formData.append('text', text);
      }
      if (files.length > 0) {
        formData.append('file', files[0]);
      }
      // 统一处理方式
      const actualMethod = processingMethod === 'nlp' ? 'machine' : processingMethod;
      formData.append('method', actualMethod);
      if (apiKey) {
        formData.append('apiKey', apiKey);
      }
      if (processingMethod === 'api') {
        formData.append('provider', llmProvider);
      }

      const token = localStorage.getItem('token');
      if (!token) {
        throw new Error('请先登录');
      }

      const response = await fetch(`${API_BASE_URL}/process`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`
        },
        body: formData
      });

      if (!response.ok) {
        const errorData = await response.json();
        if (response.status === 401) {
          handleLogout();
          throw new Error('登录已过期，请重新登录');
        }
        throw new Error(errorData.message || '处理失败');
      }

      const result = await response.json();
      
      if (!result.success) {
        throw new Error(result.message || '处理失败');
      }
      
      // 确保设置处理时间和统一处理方式
      const processedResult = {
        ...result.data,
        processedAt: result.data?.processedAt || new Date().toISOString(),
        provider: processingMethod === 'nlp' ? 'machine' : result.data?.provider || processingMethod
      };
      
      setResult(processedResult);
      setIsEditing(true);
      fetchResults();
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : '处理失败，请重试');
    } finally {
      setProcessing(false);
    }
  };

  const handleDelete = async (id: string) => {
    if (!window.confirm('确定要删除这条记录吗？')) {
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/results/${id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });

      const data = await response.json();
      
      if (data.success) {
        setErrorMessage('删除成功');
        // 刷新列表
        fetchResults();
      } else {
        throw new Error(data.message || '删除失败');
      }
    } catch (error) {
      console.error('删除错误:', error);
      setErrorMessage(error instanceof Error ? error.message : '删除失败，请重试');
    }
  };

  const handleSave = async () => {
    if (!result) return;
    
    try {
      const url = result.id ? 
        `${API_BASE_URL}/results/${result.id}` : 
        `${API_BASE_URL}/save`;

      const method = result.id ? 'PUT' : 'POST';
      
      // 确保有处理时间和统一处理方式
      const dataToSave = {
        ...result,
        processedAt: result.processedAt || new Date().toISOString(),
        provider: result.provider === 'nlp' ? 'machine' : result.provider // 将'nlp'统一转换为'machine'
      };

      // 防止重复点击
      if (processing) return;
      setProcessing(true);
      
      const response = await fetch(url, {
        method,
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(dataToSave)
      });
      
      const data = await response.json();
      
      if (data.success) {
        // 如果是新保存的记录，更新处理时间和处理方式
        if (!result.id && data.data?.processedAt) {
          setResult(prev => prev ? { 
            ...prev, 
            processedAt: data.data.processedAt,
            provider: prev.provider === 'nlp' ? 'machine' : prev.provider // 确保本地状态也更新
          } : null);
        }
        
        setErrorMessage(result.id ? '更新成功' : '保存成功');
        setIsEditing(false);
        // 刷新历史记录
        await fetchResults();
      } else {
        throw new Error(data.message || '保存失败');
      }
    } catch (error) {
      console.error('保存错误:', error);
      setErrorMessage(error instanceof Error ? error.message : '保存失败，请重试');
    } finally {
      setProcessing(false);
    }
  };

  // 获取用户列表
  const fetchUsers = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/users`, {
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        }
      });
      
      if (response.ok) {
        const data = await response.json();
        if (data.success && Array.isArray(data.data)) {
          setUsers(data.data);
        } else {
          throw new Error(data.message || '获取用户列表失败');
        }
      } else {
        throw new Error('获取用户列表失败');
      }
    } catch (error) {
      console.error('获取用户列表失败:', error);
      setErrorMessage(error instanceof Error ? error.message : '获取用户列表失败');
    }
  };

  // 在用户登录后获取用户列表
  useEffect(() => {
    if (isLoggedIn && user?.isAdmin) {
      fetchUsers();
    }
  }, [isLoggedIn, user?.isAdmin]);

  // 更新用户状态
  const updateUserStatus = async (userId: string, status: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/users/${userId}/status`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ status })
      });

      if (response.ok) {
        await fetchUsers(); // 重新获取用户列表
        setErrorMessage('用户状态更新成功');
      } else {
        const data = await response.json();
        throw new Error(data.message || '更新用户状态失败');
      }
    } catch (error) {
      console.error('更新用户状态失败:', error);
      setErrorMessage(error instanceof Error ? error.message : '更新用户状态失败');
    }
  };

  // 设置/取消管理员权限
  const updateUserAdmin = async (userId: string, isAdmin: boolean) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/users/${userId}/admin`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ isAdmin })
      });

      if (response.ok) {
        await fetchUsers(); // 重新获取用户列表
        setErrorMessage(`${isAdmin ? '设置' : '取消'}管理员权限成功`);
      } else {
        const data = await response.json();
        throw new Error(data.message || '更新管理员权限失败');
      }
    } catch (error) {
      console.error('更新管理员权限失败:', error);
      setErrorMessage(error instanceof Error ? error.message : '更新管理员权限失败');
    }
  };

  // 重置用户密码
  const resetUserPassword = async (userId: string, newPassword: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/api/users/${userId}/reset-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ newPassword })
      });

      if (response.ok) {
        setErrorMessage('密码重置成功');
      } else {
        const data = await response.json();
        throw new Error(data.message || '重置密码失败');
      }
    } catch (error) {
      console.error('重置密码失败:', error);
      setErrorMessage(error instanceof Error ? error.message : '重置密码失败');
    }
  };

  // 修改用户密码
  const changePassword = async (oldPassword: string, newPassword: string) => {
    try {
      const response = await fetch(`${API_BASE_URL}/user/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ oldPassword, newPassword })
      });

      if (response.ok) {
        setErrorMessage('密码修改成功');
      } else {
        const data = await response.json();
        throw new Error(data.message || '密码修改失败');
      }
    } catch (error) {
      console.error('密码修改失败:', error);
      setErrorMessage(error instanceof Error ? error.message : '密码修改失败');
    }
  };

  const handleUpdateHomework = async (updatedHomework: ProcessedResult) => {
    try {
      console.log('正在更新作业:', updatedHomework);

      const response = await fetch(`${API_BASE_URL}/results/${updatedHomework.id}`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({
          content: updatedHomework.content,
          subject: updatedHomework.subject,
          course: updatedHomework.course,
          dueDate: updatedHomework.dueDate,
          difficulty: updatedHomework.difficulty,
          isCompleted: updatedHomework.isCompleted,
          score: updatedHomework.score,
          timeSpent: updatedHomework.timeSpent
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || '更新作业失败');
      }

      const data = await response.json();
      console.log('更新响应数据:', data);

      setErrorMessage('作业更新成功');
      setEditingHomework(null);
      await fetchResults(); // 刷新列表
    } catch (error) {
      console.error('更新作业失败:', error);
      setErrorMessage(error instanceof Error ? error.message : '更新作业失败');
    }
  };

  // 渲染用户管理界面
  const renderUserManagement = () => {
    if (!user) return null;

    return (
      <div className="manage-page">
        {/* API密钥管理部分 - 所有用户都可见 */}
        <div className="manage-section">
          <h2>API密钥管理</h2>
          <div className="api-keys-grid">
            {Object.values(LLMProvider).map((provider) => (
              <div key={provider} className="api-key-item">
                <label>{getProviderDisplayName(provider)} API Key:</label>
                <input
                  type="password"
                  value={user?.apiKeys?.[provider] || ''}
                  onChange={(e) => updateApiKey(provider, e.target.value)}
                  placeholder={`输入${getProviderDisplayName(provider)} API Key`}
                />
              </div>
            ))}
          </div>
        </div>

        {/* 账号管理部分 - 所有用户都可见 */}
        <div className="manage-section">
          <h2>账号管理</h2>
          <div className="account-info">
            <div className="info-item">
              <label>用户名:</label>
              <span>{user.username}</span>
            </div>
            <div className="info-item">
              <label>账号创建时间:</label>
              <span>{new Date(user.createdAt).toLocaleString()}</span>
            </div>
            <div className="info-item">
              <label>最后登录时间:</label>
              <span>{user.lastLoginAt ? new Date(user.lastLoginAt).toLocaleString() : '首次登录'}</span>
            </div>
            <div className="password-change-section">
              <h3>修改密码</h3>
              <div className="password-form">
                <div className="form-group">
                  <label>当前密码:</label>
                  <input
                    type="password"
                    id="oldPassword"
                    placeholder="请输入当前密码"
                  />
                </div>
                <div className="form-group">
                  <label>新密码:</label>
                  <input
                    type="password"
                    id="newPassword"
                    placeholder="请输入新密码（至少6个字符）"
                  />
                </div>
                <div className="form-group">
                  <label>确认新密码:</label>
                  <input
                    type="password"
                    id="confirmPassword"
                    placeholder="请再次输入新密码"
                  />
                </div>
                <button
                  className="change-password-button"
                  onClick={() => {
                    const oldPassword = (document.getElementById('oldPassword') as HTMLInputElement).value;
                    const newPassword = (document.getElementById('newPassword') as HTMLInputElement).value;
                    const confirmPassword = (document.getElementById('confirmPassword') as HTMLInputElement).value;

                    if (!oldPassword || !newPassword || !confirmPassword) {
                      setErrorMessage('请填写所有密码字段');
                      return;
                    }

                    if (newPassword.length < 6) {
                      setErrorMessage('新密码长度不能少于6个字符');
                      return;
                    }

                    if (newPassword !== confirmPassword) {
                      setErrorMessage('两次输入的新密码不一致');
                      return;
                    }

                    changePassword(oldPassword, newPassword);
                    
                    // 清空输入框
                    (document.getElementById('oldPassword') as HTMLInputElement).value = '';
                    (document.getElementById('newPassword') as HTMLInputElement).value = '';
                    (document.getElementById('confirmPassword') as HTMLInputElement).value = '';
                  }}
                >
                  修改密码
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* 用户管理部分 - 仅管理员可见 */}
        {user.isAdmin && (
          <div className="manage-section">
            <h2>用户管理</h2>
            <div className="table-container">
              <table className="data-table">
                <thead>
                  <tr>
                    <th>用户名</th>
                    <th>API配置状态</th>
                    <th>作业数量</th>
                    <th>管理员</th>
                    <th>状态</th>
                    <th>操作</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map(user => (
                    <tr key={user.username}>
                      <td>{user.username}</td>
                      <td>{Object.values(user.apiKeys).some(key => key && key.length > 0) ? '已配置' : '未配置'}</td>
                      <td>{user.homeworkCount || 0}</td>
                      <td>
                        <input
                          type="checkbox"
                          checked={user.isAdmin}
                          onChange={(e) => updateUserAdmin(user._id, e.target.checked)}
                        />
                      </td>
                      <td>
                        <select
                          value={user.status}
                          onChange={(e) => updateUserStatus(user._id, e.target.value)}
                          className="status-select"
                        >
                          <option value="active">启用</option>
                          <option value="disabled">禁用</option>
                        </select>
                      </td>
                      <td>
                        <button 
                          onClick={() => {
                            const newPassword = prompt('请输入新密码（至少6个字符）');
                            if (newPassword && newPassword.length >= 6) {
                              resetUserPassword(user._id, newPassword);
                            } else if (newPassword) {
                              alert('密码长度不能少于6个字符');
                            }
                          }}
                          className="action-button"
                        >
                          重置密码
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="container">
      <header className="header">
        <h1 className="title">作业信息系统</h1>
        <div className="auth-buttons">
          {!isLoggedIn ? (
            <>
              <button onClick={() => setShowLoginForm(true)} className="login-button">
                登录
              </button>
              <button onClick={() => setShowRegisterForm(true)} className="register-button">
                注册
              </button>
            </>
          ) : (
            <div className="user-info">
              <span>欢迎, {user?.username}</span>
              <button onClick={handleLogout} className="logout-button">
                退出
              </button>
            </div>
          )}
        </div>
      </header>

      <div className="main-content">
        {isLoggedIn && (
          <nav className="navigation">
            <button 
              className={`nav-button ${currentPage === Page.INPUT ? 'active' : ''}`}
              onClick={() => setCurrentPage(Page.INPUT)}
              data-page="input"
            >
              📝 录入
            </button>
            <button 
              className={`nav-button ${currentPage === Page.VIEW ? 'active' : ''}`}
              onClick={() => setCurrentPage(Page.VIEW)}
              data-page="view"
            >
              📋 查看
            </button>
            <button 
              className={`nav-button ${currentPage === Page.STATISTICS ? 'active' : ''}`}
              onClick={() => setCurrentPage(Page.STATISTICS)}
              data-page="statistics"
            >
              📊 统计
            </button>
            <button 
              className={`nav-button ${currentPage === Page.MANAGE ? 'active' : ''}`}
              onClick={() => setCurrentPage(Page.MANAGE)}
              data-page="manage"
            >
              ⚙️ 管理
            </button>
          </nav>
        )}

        {showLoginForm && (
          <div className="modal">
            <div className="modal-content">
              <h2>登录</h2>
              <input
                type="text"
                placeholder="用户名"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
              <input
                type="password"
                placeholder="密码"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <div className="modal-buttons">
                <button onClick={handleLogin}>登录</button>
                <button onClick={() => setShowLoginForm(false)}>取消</button>
              </div>
            </div>
          </div>
        )}

        {showRegisterForm && (
          <div className="modal">
            <div className="modal-content">
              <h2>注册</h2>
              <input
                type="text"
                placeholder="用户名"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
              <input
                type="password"
                placeholder="密码"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <div className="modal-buttons">
                <button onClick={handleRegister}>注册</button>
                <button onClick={() => setShowRegisterForm(false)}>取消</button>
              </div>
            </div>
          </div>
        )}

        {isLoggedIn && (
          <div className="page-content">
            {currentPage === Page.INPUT && (
              <div className="input-page">
                <div className="input-section">
                  {errorMessage && (
                    <div className="error-message">
                      {errorMessage}
                    </div>
                  )}
                  
                  <div className="text-input">
                    <h3>文本输入</h3>
                    <textarea
                      value={text}
                      onChange={(e) => setText(e.target.value)}
                      placeholder="请输入作业相关文本..."
                      className="text-area"
                    />
                  </div>

                  <div className="image-input">
                    <h3>图片上传</h3>
                    <div {...getRootProps()} className={`dropzone ${isDragActive ? 'active' : ''}`}>
                      <input {...getInputProps()} />
                      {isDragActive ? (
                        <p>放开以上传图片...</p>
                      ) : (
                        <p>拖放图片到这里，或点击选择图片</p>
                      )}
                    </div>
                    {files.length > 0 && (
                      <div className="file-list">
                        <p>已选择: {files[0].name}</p>
                      </div>
                    )}
                  </div>

                  <div className="processing-options">
                    <h3>处理方式</h3>
                    <div className="radio-group">
                      <label>
                        <input
                          type="radio"
                          checked={processingMethod === 'nlp'}
                          onChange={() => handleProcessingMethodChange('nlp')}
                        />
                        机器处理
                      </label>
                      <label>
                        <input
                          type="radio"
                          checked={processingMethod === 'api'}
                          onChange={() => handleProcessingMethodChange('api')}
                        />
                        AI处理
                      </label>
                    </div>

                    {processingMethod === 'api' && (
                      <div className="llm-provider-select">
                        <h4>选择LLM提供商</h4>
                        <select
                          value={llmProvider}
                          onChange={(e) => setLLMProvider(e.target.value as LLMProvider)}
                          className="provider-select"
                        >
                          <option value={LLMProvider.DEEPSEEK}>Deepseek</option>
                          <option value={LLMProvider.DOUBAO}>豆包AI</option>
                        </select>
                      </div>
                    )}

                    {showApiKeyInput && (
                      <div className="api-key-input">
                        <input
                          type="text"
                          value={apiKey}
                          onChange={(e) => setApiKey(e.target.value)}
                          placeholder={`请输入${getProviderDisplayName(llmProvider)} API Key`}
                          className="api-key-field"
                        />
                      </div>
                    )}
                  </div>

                  <button 
                    onClick={handleSubmit}
                    disabled={processing || (!text && files.length === 0)}
                    className="submit-button"
                  >
                    {processing ? '处理中...' : '开始处理'}
                  </button>
                </div>

                {result && (
                  <div className="result-section">
                    <h3>处理结果</h3>
                    {isEditing ? (
                      <div className="result-edit">
                        <div className="form-group">
                          <label>作业内容:</label>
                          <textarea
                            value={result.content}
                            onChange={(e) => setResult({ ...result, content: e.target.value })}
                          />
                        </div>
                        <div className="form-group">
                          <label>学科:</label>
                          <input
                            type="text"
                            value={result.subject}
                            onChange={(e) => setResult({ ...result, subject: e.target.value })}
                          />
                        </div>
                        <div className="form-group">
                          <label>课程:</label>
                          <input
                            type="text"
                            value={result.course}
                            onChange={(e) => setResult({ ...result, course: e.target.value })}
                          />
                        </div>
                        <div className="form-group">
                          <label>截止日期:</label>
                          <div className="date-time-inputs">
                            <input
                              type="date"
                              value={result.dueDate ? result.dueDate.split('T')[0] : ''}
                              onChange={(e) => {
                                const date = e.target.value;
                                const time = result.dueDate ? result.dueDate.split('T')[1].split('.')[0] : '23:59:59';
                                setResult({
                                  ...result,
                                  dueDate: `${date}T${time}`
                                });
                              }}
                            />
                            <input
                              type="time"
                              value={result.dueDate ? result.dueDate.split('T')[1].split('.')[0] : '23:59:59'}
                              onChange={(e) => {
                                const date = result.dueDate ? result.dueDate.split('T')[0] : new Date().toISOString().split('T')[0];
                                setResult({
                                  ...result,
                                  dueDate: `${date}T${e.target.value}`
                                });
                              }}
                            />
                          </div>
                          {result.dueDateOriginal && (
                            <div className="date-info">
                              <p>原始日期文本: {result.dueDateOriginal}</p>
                              <p>日期识别置信度: {(result.dueDateConfidence || 0) * 100}%</p>
                            </div>
                          )}
                        </div>
                        {result.confidence !== undefined && (
                          <div className="confidence-info">
                            <p>整体置信度: {(result.confidence * 100).toFixed(1)}%</p>
                          </div>
                        )}
                        {result.suggestions && result.suggestions.length > 0 && (
                          <div className="suggestions">
                            <h4>改进建议:</h4>
                            <ul>
                              {result.suggestions.map((suggestion, index) => (
                                <li key={index}>{suggestion}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                        {result.processedAt && (
                          <div className="process-info">
                            <p>处理时间: {new Date(result.processedAt).toLocaleString()}</p>
                            <p>处理方式: {getProviderDisplayName(result.provider as LLMProvider)}</p>
                          </div>
                        )}
                        <button onClick={handleSave} className="save-button">
                          保存
                        </button>
                      </div>
                    ) : (
                      <div className="result-display">
                        <p><strong>作业内容:</strong> {result.content}</p>
                        <p><strong>学科:</strong> {result.subject}</p>
                        <p><strong>课程:</strong> {result.course}</p>
                        <p><strong>截止日期:</strong> {result.dueDate ? new Date(result.dueDate).toLocaleString() : '未设置'}</p>
                        {result.dueDateOriginal && (
                          <p><strong>原始日期文本:</strong> {result.dueDateOriginal}</p>
                        )}
                        {result.dueDateConfidence !== undefined && (
                          <p><strong>日期识别置信度:</strong> {(result.dueDateConfidence * 100).toFixed(1)}%</p>
                        )}
                        {result.confidence !== undefined && (
                          <p><strong>整体置信度:</strong> {(result.confidence * 100).toFixed(1)}%</p>
                        )}
                        {result.suggestions && result.suggestions.length > 0 && (
                          <div>
                            <strong>改进建议:</strong>
                            <ul>
                              {result.suggestions.map((suggestion, index) => (
                                <li key={index}>{suggestion}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                        {result.processedAt && (
                          <div>
                            <p><strong>处理时间:</strong> {new Date(result.processedAt).toLocaleString()}</p>
                            <p><strong>处理方式:</strong> {getProviderDisplayName(result.provider as LLMProvider)}</p>
                          </div>
                        )}
                        <button onClick={() => setIsEditing(true)} className="edit-button">
                          编辑
                        </button>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {currentPage === Page.VIEW && (
              <div className="view-page">
                {errorMessage && (
                  <div className="error-message">{errorMessage}</div>
                )}
                {editingHomework ? (
                  <EditHomework
                    homework={editingHomework}
                    onSave={handleUpdateHomework}
                    onCancel={() => setEditingHomework(null)}
                  />
                ) : (
                  results.length === 0 ? (
                    <div className="empty-message">
                      暂无作业记录
                    </div>
                  ) : (
                    <div className="homework-table">
                      <table>
                        <thead>
                          <tr>
                            <th>作业内容</th>
                            <th>学科</th>
                            <th>课程</th>
                            <th>截止日期</th>
                            <th>难度</th>
                            <th>状态</th>
                            <th>分数</th>
                            <th>用时</th>
                            <th>处理方式</th>
                            <th>创建时间</th>
                            <th>操作</th>
                          </tr>
                        </thead>
                        <tbody>
                          {results.map((result) => (
                            <tr key={result.id} className={result.isCompleted ? 'completed' : ''}>
                              <td>{result.content}</td>
                              <td>{result.subject}</td>
                              <td>{result.course}</td>
                              <td>{result.dueDate ? new Date(result.dueDate).toLocaleString() : '未设置'}</td>
                              <td>
                                <span className={`difficulty-badge ${result.difficulty || 'medium'}`}>
                                  {result.difficulty === 'easy' ? '简单' :
                                   result.difficulty === 'medium' ? '中等' :
                                   result.difficulty === 'hard' ? '困难' : '未设置'}
                                </span>
                              </td>
                              <td>
                                <span className={`status-badge ${result.isCompleted ? 'completed' : 'pending'}`}>
                                  {result.isCompleted ? '已完成' : '未完成'}
                                </span>
                              </td>
                              <td>{result.score !== null && result.score !== undefined ? result.score : '未评分'}</td>
                              <td>{result.timeSpent !== null && result.timeSpent !== undefined ? `${result.timeSpent}分钟` : '未记录'}</td>
                              <td>{result.provider ? getProviderDisplayName(result.provider as LLMProvider) : '机器处理'}</td>
                              <td>{result.createdAt ? new Date(result.createdAt).toLocaleString() : '未知'}</td>
                              <td>
                                <div className="action-buttons">
                                  <button 
                                    onClick={() => setEditingHomework(result)}
                                    className="edit-button"
                                  >
                                    编辑
                                  </button>
                                  <button 
                                    onClick={() => result.id && handleDelete(result.id)}
                                    className="delete-button"
                                  >
                                    删除
                                  </button>
                                </div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )
                )}
              </div>
            )}

            {currentPage === Page.MANAGE && renderUserManagement()}
            {currentPage === Page.STATISTICS && <Statistics />}
          </div>
        )}
      </div>
    </div>
  )
}

export default App
