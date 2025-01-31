import { useState, useCallback, useEffect } from 'react'
import { useDropzone } from 'react-dropzone'
import './App.css'

enum LLMProvider {
  OPENAI = 'openai',
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
}

interface ApiResponse {
  success: boolean
  data?: ProcessedResult
  error?: string
  details?: any
  message: string
}

interface User {
  username: string
  apiKeys: {
    [key in LLMProvider]: string
  }
}

interface AuthResponse {
  token: string
  user: User
  message?: string
}

// 添加API基础URL常量
const API_BASE_URL = 'http://localhost:3000';

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
  const [llmProvider, setLLMProvider] = useState<LLMProvider>(LLMProvider.OPENAI)
  const [user, setUser] = useState<User | null>(null)
  const [showLoginForm, setShowLoginForm] = useState(false)
  const [showRegisterForm, setShowRegisterForm] = useState(false)
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [results, setResults] = useState<ProcessedResult[]>([])

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
      })
      if (response.ok) {
        const data = await response.json()
        setResults(data)
      }
    } catch (error) {
      console.error('获取历史记录失败:', error)
    }
  }

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
      const response = await fetch(`${API_BASE_URL}/user/api-keys`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify({ provider, apiKey: newApiKey })
      })

      if (response.ok) {
        setUser(prev => prev ? {
          ...prev,
          apiKeys: {
            ...prev.apiKeys,
            [provider]: newApiKey
          }
        } : null)
        setErrorMessage('API密钥更新成功')
      } else {
        const data = await response.json()
        setErrorMessage(data.message || 'API密钥更新失败')
      }
    } catch (error) {
      setErrorMessage('API密钥更新失败，请重试')
    }
  }

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
      case LLMProvider.OPENAI:
        return 'OpenAI';
      case LLMProvider.DEEPSEEK:
        return 'Deepseek';
      case LLMProvider.DOUBAO:
        return '豆包AI';
      default:
        return provider;
    }
  };

  const handleSubmit = async () => {
    if (!text && files.length === 0) return
    if (processingMethod === 'api' && !isLoggedIn) {
      setErrorMessage('请先登录')
      return
    }
    
    setProcessing(true)
    setErrorMessage(null)
    try {
      const formData = new FormData()
      if (text) {
        formData.append('text', text)
      }
      if (files.length > 0) {
        formData.append('file', files[0])
      }
      formData.append('method', processingMethod)
      if (apiKey) {
        formData.append('apiKey', apiKey)
      }
      if (processingMethod === 'api') {
        formData.append('provider', llmProvider)
      }

      const response = await fetch(`${API_BASE_URL}/process`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: formData
      })

      const result: ApiResponse = await response.json()
      
      if (!result.success) {
        throw new Error(result.message || '处理失败')
      }
      
      setResult(result.data || null)
      setIsEditing(true)
      fetchResults() // 刷新历史记录
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : '处理失败，请重试')
    } finally {
      setProcessing(false)
    }
  }

  const handleSave = async () => {
    if (!result) return
    
    try {
      const response = await fetch(`${API_BASE_URL}/save`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('token')}`
        },
        body: JSON.stringify(result)
      })
      
      if (response.ok) {
        alert('保存成功')
        setIsEditing(false)
      }
    } catch (error) {
      alert('保存失败，请重试')
    }
  }

  return (
    <div className="container">
      <header className="header">
        <h1 className="title">作业信息提取系统</h1>
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
        <div className="api-keys-section">
          <h3>API密钥管理</h3>
          <div className="api-keys-grid">
            {Object.values(LLMProvider).map((provider) => (
              <div key={provider} className="api-key-item">
                <label>{getProviderDisplayName(provider)} API Key:</label>
                <input
                  type="password"
                  value={user?.apiKeys[provider] || ''}
                  onChange={(e) => updateApiKey(provider, e.target.value)}
                  placeholder={`输入${getProviderDisplayName(provider)} API Key`}
                />
              </div>
            ))}
          </div>
        </div>
      )}

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
              NLP处理
            </label>
            <label>
              <input
                type="radio"
                checked={processingMethod === 'api'}
                onChange={() => handleProcessingMethodChange('api')}
              />
              API处理
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
                <option value={LLMProvider.OPENAI}>OpenAI</option>
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

      {results.length > 0 && (
        <div className="history-section">
          <h3>历史记录</h3>
          <div className="history-list">
            {results.map((result, index) => (
              <div key={index} className="history-item">
                <p><strong>内容:</strong> {result.content}</p>
                <p><strong>学科:</strong> {result.subject}</p>
                <p><strong>课程:</strong> {result.course}</p>
                <p><strong>截止日期:</strong> {result.dueDate ? new Date(result.dueDate).toLocaleString() : '未设置'}</p>
                <p><strong>处理时间:</strong> {result.processedAt ? new Date(result.processedAt).toLocaleString() : '未知'}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

export default App
