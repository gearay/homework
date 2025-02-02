import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { createWorker } from 'tesseract.js';
import natural from 'natural';
import { MongoClient, ObjectId } from 'mongodb';
import dotenv from 'dotenv';
import path from 'path';
import axios from 'axios';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

dotenv.config();

const app = express();
const upload = multer({ dest: 'uploads/' });

// CORS配置
const corsOptions = {
  origin: ['http://localhost:5173', 'http://127.0.0.1:5173'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
};

app.use(cors(corsOptions));
app.use(express.json());

// MongoDB连接
const mongoClient = new MongoClient(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017', {
  connectTimeoutMS: 5000,
  socketTimeoutMS: 45000,
});
let db;

async function connectDB() {
  try {
    console.log('正在连接到MongoDB...');
    console.log('连接URL:', process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017');
    await mongoClient.connect();
    console.log('MongoDB连接成功');
    
    db = mongoClient.db('homework_system');
    console.log('已选择数据库:', db.databaseName);
    
    // 测试数据库连接
    await db.command({ ping: 1 });
    console.log('数据库连接测试成功');
    
    // 创建必要的索引
    console.log('创建索引...');
    await db.collection('users').createIndex({ username: 1 }, { unique: true });
    await db.collection('results').createIndex({ userId: 1 }); // 为作业数量统计创建索引
    await db.collection('results').createIndex({ userId: 1, createdAt: -1 }); // 为按时间排序的查询创建复合索引
    console.log('索引创建完成');

    // 检查users集合是否存在
    const collections = await db.listCollections().toArray();
    const hasUsers = collections.some(col => col.name === 'users');
    console.log('users集合状态:', hasUsers ? '已存在' : '不存在');
    
    if (!hasUsers) {
      await db.createCollection('users');
      console.log('users集合已创建');
    }
  } catch (error) {
    console.error('MongoDB连接错误:', error);
    console.error('错误详情:', {
      name: error.name,
      message: error.message,
      code: error.code,
      stack: error.stack
    });
    process.exit(1);
  }
}

// 确保数据库连接
const ensureDbConnected = (req, res, next) => {
  if (!db) {
    console.error('数据库未连接');
    return res.status(500).json({ 
      success: false,
      message: '数据库未连接，请稍后重试' 
    });
  }
  next();
};

// 启动数据库连接
connectDB().then(() => {
  console.log('数据库初始化完成');
}).catch(error => {
  console.error('数据库初始化失败:', error);
  process.exit(1);
});

app.use(ensureDbConnected);

// JWT中间件
const authenticateToken = async (req, res, next) => {
  try {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
      return res.status(401).json({ 
        success: false,
        message: '请先登录' 
      });
  }

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
      // 验证用户是否存在
      const userExists = await db.collection('users').findOne({ 
        _id: new ObjectId(user.id) 
      });
      
      if (!userExists) {
        return res.status(401).json({ 
          success: false,
          message: '用户不存在' 
        });
      }
      
    req.user = user;
    next();
  } catch (error) {
      console.error('Token验证错误:', error);
      return res.status(401).json({ 
        success: false,
        message: '无效的认证令牌' 
      });
    }
  } catch (error) {
    console.error('认证中间件错误:', error);
    return res.status(500).json({ 
      success: false,
      message: '服务器错误' 
    });
  }
};

// 管理员验证中间件
const isAdmin = async (req, res, next) => {
  try {
    const user = await db.collection('users').findOne({ 
      _id: new ObjectId(req.user.id) 
    });

    if (!user || !user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: '需要管理员权限'
      });
    }
    next();
  } catch (error) {
    console.error('管理员验证错误:', error);
    res.status(500).json({
      success: false,
      message: '服务器错误'
    });
  }
};

// 获取用户列表（仅管理员可访问）
app.get('/api/users', authenticateToken, isAdmin, async (req, res) => {
  try {
    // 首先获取所有用户的基本信息
    const users = await db.collection('users').find({}, {
      projection: {
        password: 0 // 不返回密码字段
      }
    }).toArray();

    // 使用聚合管道获取每个用户的作业数量
    const userHomeworkCounts = await db.collection('results').aggregate([
      {
        $group: {
          _id: '$userId',
          homeworkCount: { $sum: 1 }
        }
      }
    ]).toArray();

    // 创建一个用户ID到作业数量的映射
    const homeworkCountMap = new Map(
      userHomeworkCounts.map(item => [item._id.toString(), item.homeworkCount])
    );

    // 合并用户信息和作业数量
    const usersWithStats = users.map(user => ({
      ...user,
      homeworkCount: homeworkCountMap.get(user._id.toString()) || 0,
      apiKeysConfigured: Object.values(user.apiKeys).some(key => key && key.length > 0)
    }));

    console.log('用户统计信息:', usersWithStats.map(user => ({
      username: user.username,
      homeworkCount: user.homeworkCount,
      apiKeysConfigured: user.apiKeysConfigured
    })));

    res.json({
      success: true,
      data: usersWithStats
    });
  } catch (error) {
    console.error('获取用户列表错误:', error);
    res.status(500).json({
      success: false,
      message: '获取用户列表失败'
    });
  }
});

// 更新用户状态（仅管理员可访问）
app.put('/api/users/:userId/status', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { status } = req.body;

    if (!['active', 'disabled'].includes(status)) {
      return res.status(400).json({
        success: false,
        message: '无效的状态值'
      });
    }

    const result = await db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { 
        $set: { 
          status: status,
          isDisabled: status === 'disabled',
          updatedAt: new Date().toISOString()
        } 
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: '用户不存在'
      });
    }

    res.json({
      success: true,
      message: '用户状态更新成功'
    });
  } catch (error) {
    console.error('更新用户状态错误:', error);
    res.status(500).json({
      success: false,
      message: '更新用户状态失败'
    });
  }
});

// 设置/取消管理员权限（仅管理员可访问）
app.put('/api/users/:userId/admin', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { isAdmin: setAdmin } = req.body;

    const result = await db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { $set: { isAdmin: setAdmin } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: '用户不存在'
      });
    }

    res.json({
      success: true,
      message: `${setAdmin ? '设置' : '取消'}管理员权限成功`
    });
  } catch (error) {
    console.error('更新管理员权限错误:', error);
    res.status(500).json({
      success: false,
      message: '更新管理员权限失败'
    });
  }
});

// 重置用户密码（仅管理员可访问）
app.post('/api/users/:userId/reset-password', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({
        success: false,
        message: '新密码长度不能少于6个字符'
      });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    const result = await db.collection('users').updateOne(
      { _id: new ObjectId(userId) },
      { $set: { password: hashedPassword } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: '用户不存在'
      });
    }

    res.json({
      success: true,
      message: '密码重置成功'
    });
  } catch (error) {
    console.error('重置密码错误:', error);
    res.status(500).json({
      success: false,
      message: '重置密码失败'
    });
  }
});

// 用户注册
app.post('/auth/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    // 验证用户名和密码
    if (!username || !password) {
      return res.status(400).json({ 
        success: false,
        message: '用户名和密码不能为空' 
      });
    }

    if (username.length < 3 || username.length > 20) {
      return res.status(400).json({
        success: false,
        message: '用户名长度必须在3-20个字符之间'
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: '密码长度不能少于6个字符'
      });
    }

    // 检查用户是否已存在
    const existingUser = await db.collection('users').findOne({ 
      username: { $regex: new RegExp(`^${username}$`, 'i') } 
    });
    
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: '用户名已存在'
      });
    }

    // 加密密码
    const hashedPassword = await bcrypt.hash(password, 10);

    // 创建用户
    const user = {
      username,
      password: hashedPassword,
      isAdmin: false,
      status: 'active',
      apiKeys: {
        openai: '',
        deepseek: '',
        doubao: ''
      },
      createdAt: new Date(),
      lastLoginAt: null
    };

    const result = await db.collection('users').insertOne(user);
    
    if (!result.acknowledged) {
      throw new Error('用户创建失败');
    }

    res.status(201).json({ 
      success: true,
      message: '注册成功' 
    });
  } catch (error) {
    console.error('注册错误:', error);
    
    // 根据错误类型返回不同的错误信息
    if (error.code === 11000) {  // MongoDB重复键错误
      res.status(400).json({
        success: false,
        message: '用户名已存在'
      });
    } else {
      res.status(500).json({
        success: false,
        message: '注册失败，请稍后重试',
        error: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
});

// 用户登录
app.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    console.log('登录请求:', { username });

    // 查找用户
    const user = await db.collection('users').findOne({ username });
    console.log('查找用户结果:', user ? '用户存在' : '用户不存在');
    console.log('用户详情:', {
      username: user?.username,
      isAdmin: user?.isAdmin,
      status: user?.status
    });
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: '用户名或密码错误' 
      });
    }

    // 检查用户状态
    if (user.isDisabled || user.status === 'disabled') {
      return res.status(401).json({
        success: false,
        message: '账户已被禁用，请联系管理员'
      });
    }

    // 验证密码
    const validPassword = await bcrypt.compare(password, user.password);
    console.log('密码验证结果:', validPassword ? '密码正确' : '密码错误');
    
    if (!validPassword) {
      return res.status(401).json({ 
        success: false,
        message: '用户名或密码错误' 
      });
    }

    // 更新最后登录时间和确保状态字段一致
    await db.collection('users').updateOne(
      { _id: user._id },
      { 
        $set: { 
          lastLoginAt: new Date(),
          status: user.isDisabled ? 'disabled' : 'active',  // 添加status字段
          isDisabled: user.status === 'disabled'  // 同步isDisabled字段
        } 
      }
    );

    // 生成JWT令牌，确保包含isAdmin信息
    const token = jwt.sign(
      { 
        id: user._id,
        username: user.username,
        isAdmin: user.isAdmin || false
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // 返回用户信息（不包含密码）
    const userResponse = {
      _id: user._id,
      username: user.username,
      isAdmin: user.isAdmin || false,
      status: user.isDisabled ? 'disabled' : 'active',
      apiKeys: user.apiKeys || {},
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt
    };

    console.log('登录成功，返回用户信息:', {
      username: userResponse.username,
      isAdmin: userResponse.isAdmin,
      status: userResponse.status
    });

    res.json({
      success: true,
      token,
      user: userResponse
    });
  } catch (error) {
    console.error('登录错误:', error);
    console.error('错误详情:', {
      name: error.name,
      message: error.message,
      code: error.code,
      stack: error.stack
    });
    res.status(500).json({ 
      success: false,
      message: '登录失败，请重试',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 获取用户API密钥
app.get('/user/api-keys', authenticateToken, async (req, res) => {
  try {
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(req.user.id) },
      { projection: { apiKeys: 1 } }
    );
    
    if (!user) {
      return res.status(404).json({ message: '用户不存在' });
    }
    
    res.json(user.apiKeys);
  } catch (error) {
    console.error('获取API密钥错误:', error);
    res.status(500).json({ message: '获取API密钥失败' });
  }
});

// 更新用户API密钥
app.put('/user/api-keys', authenticateToken, async (req, res) => {
  try {
    const { provider, apiKey } = req.body;
    
    if (!provider || !apiKey) {
      return res.status(400).json({
        success: false,
        message: '提供商和API密钥不能为空'
      });
    }
    
    // 验证提供商
    const validProviders = ['deepseek', 'doubao'];
    if (!validProviders.includes(provider)) {
      return res.status(400).json({
        success: false,
        message: '不支持的AI提供商'
      });
    }

    // 更新用户的API密钥
    const result = await db.collection('users').updateOne(
      { _id: new ObjectId(req.user.id) },
      { 
        $set: { 
          [`apiKeys.${provider}`]: apiKey,
          updatedAt: new Date().toISOString()
        }
      }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({
        success: false,
        message: '用户不存在'
      });
    }

    // 获取更新后的用户信息
    const updatedUser = await db.collection('users').findOne(
      { _id: new ObjectId(req.user.id) },
      { projection: { apiKeys: 1 } }
    );

    res.json({
      success: true,
      message: 'API密钥更新成功',
      data: {
        apiKeys: updatedUser.apiKeys
      }
    });
  } catch (error) {
    console.error('更新API密钥错误:', error);
    res.status(500).json({
      success: false,
      message: 'API密钥更新失败，请重试',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// LLM提供商配置
const LLM_PROVIDERS = {
  OPENAI: 'openai',
  DEEPSEEK: 'deepseek',
  DOUBAO: 'doubao'
};

// OpenAI客户端初始化
const initializeOpenAI = (apiKey) => {
  return new OpenAI({
    apiKey: apiKey
  });
};

// 日期处理函数
const parseDueDate = (dateStr) => {
  if (!dateStr) return null;
  
  // 尝试解析日期
  const date = new Date(dateStr);
  if (!isNaN(date.getTime())) {
    return date.toISOString();
  }
  
  return null;
};

// 系统提示模板
const SYSTEM_PROMPT = (currentTime) => `你是一个专门处理学习任务的助手。当前时间是：${currentTime}

请从用户输入中提取以下信息：
1. 学科名称
2. 课程信息
3. 截止日期（请尽可能准确地识别日期和时间信息，考虑以下情况：
   - 明确的日期时间（如"2024年3月1日下午3点"）
   - 相对日期（如"下周五"、"后天下午"，请基于当前时间计算具体日期）
   - 模糊表述（如"月底"、"下月初"，请基于当前时间推算合理日期）
   - 如果没有明确时间，默认为当天23:59:59）

请以JSON格式返回，包含这些字段：
- subject（学科）
- course（课程）
- dueDate（截止日期，必须转换为标准格式如"2024-03-01T15:00:00"）
- dueDateConfidence（日期识别的置信度0-1）
- dueDateOriginal（原始日期文本）
- content（原始内容）
- confidence（整体置信度0-1）
- suggestions（改进建议数组）`;

// 使用GPT处理文本
const processWithGPT = async (text, apiKey) => {
  try {
    const currentTime = new Date().toLocaleString('zh-CN', { 
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      weekday: 'long'
    });
    
    const openai = initializeOpenAI(apiKey);
    const response = await openai.chat.completions.create({
      model: "gpt-3.5-turbo",
      messages: [
        {
          role: "system",
          content: SYSTEM_PROMPT(currentTime)
        },
        {
          role: "user",
          content: text
        }
      ],
      temperature: 0.3,
      response_format: { type: "json_object" }
    });

    const result = JSON.parse(response.choices[0].message.content);
    
    // 处理日期
    if (result.dueDate) {
      const parsedDate = parseDueDate(result.dueDate);
      if (parsedDate) {
        result.dueDate = parsedDate;
      }
    }
    
    // 添加处理时间
    result.processedAt = new Date().toISOString();
    
    return result;
  } catch (error) {
    console.error('GPT处理错误:', error);
    throw new Error(`GPT处理失败：${error.response?.data?.error?.message || error.message}`);
  }
};

// Deepseek API调用
const processWithDeepseek = async (text, apiKey) => {
  try {
    const currentTime = new Date().toLocaleString('zh-CN', { 
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      weekday: 'long'
    });

    const response = await axios.post('https://api.deepseek.com/v1/chat/completions', {
      model: "deepseek-chat",
      messages: [
        {
          role: "system",
          content: SYSTEM_PROMPT(currentTime)
        },
        {
          role: "user",
          content: text || ''  // 确保content字段不为空
        }
      ],
      temperature: 0.3,
      response_format: { type: "json_object" }
    }, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      }
    });

    let result;
    try {
      result = JSON.parse(response.data.choices[0].message.content);
    } catch (parseError) {
      console.error('解析Deepseek响应失败:', parseError);
      throw new Error('无法解析Deepseek的响应');
    }
    
    // 处理日期
    if (result.dueDate) {
      const parsedDate = parseDueDate(result.dueDate);
      if (parsedDate) {
        result.dueDate = parsedDate;
      }
    }

    // 确保所有必需字段都存在
    result.content = result.content || text;
    result.subject = result.subject || '';
    result.course = result.course || '';
    result.dueDateConfidence = result.dueDateConfidence || 0;
    result.confidence = result.confidence || 0;
    result.suggestions = Array.isArray(result.suggestions) ? result.suggestions : [];
    result.processedAt = new Date().toISOString();
    
    return result;
  } catch (error) {
    console.error('Deepseek处理错误:', error);
    throw new Error(`Deepseek处理失败：${error.response?.data?.error?.message || error.message}`);
  }
};

// 豆包AI API调用
const processWithDoubao = async (text, apiKey) => {
  try {
    const currentTime = new Date().toLocaleString('zh-CN', { 
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      weekday: 'long'
    });

    const response = await axios.post('https://api.doubao.com/v1/chat/completions', {
      model: "doubao-text",
      messages: [
        {
          role: "system",
          content: SYSTEM_PROMPT(currentTime)
        },
        {
          role: "user",
          content: text
        }
      ],
      temperature: 0.3,
      response_format: { type: "json_object" }
    }, {
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      }
    });

    const result = JSON.parse(response.data.choices[0].message.content);
    
    // 处理日期
    if (result.dueDate) {
      const parsedDate = parseDueDate(result.dueDate);
      if (parsedDate) {
        result.dueDate = parsedDate;
      }
    }
    
    result.processedAt = new Date().toISOString();
    return result;
  } catch (error) {
    console.error('豆包AI处理错误:', error);
    throw new Error(`豆包AI处理失败：${error.response?.data?.error?.message || error.message}`);
  }
};

// 简单的NLP处理函数
const processText = (text) => {
  if (!text) {
    return {
      content: '',
      subject: '',
      course: '',
      dueDate: '',
      confidence: 0,
      processedAt: new Date().toISOString()
    };
  }

  const tokenizer = new natural.WordTokenizer();
  const tokens = tokenizer.tokenize(text.toLowerCase());
  
  // 简单的规则匹配
  let result = {
    content: text,
    subject: '',
    course: '',
    dueDate: '',
    confidence: 0,
    processedAt: new Date().toISOString()
  };

  // 查找可能的学科
  const subjects = ['数学', '语文', '英语', '物理', '化学', '生物', '历史', '地理', '政治'];
  for (let subject of subjects) {
    if (text.includes(subject)) {
      result.subject = subject;
      result.confidence += 0.3;
      break;
    }
  }

  // 查找日期
  const datePattern = /(\d{4}年)?\d{1,2}月\d{1,2}日|(\d{4}[-/.])?\d{1,2}[-/.]\d{1,2}/g;
  const dateMatch = text.match(datePattern);
  if (dateMatch) {
    result.dueDate = dateMatch[0];
    result.confidence += 0.3;
  }

  // 提取课程信息
  const coursePattern = /(?:课程|班级|教室)[:：]?\s*([^\n,，。]+)/;
  const courseMatch = text.match(coursePattern);
  if (courseMatch) {
    result.course = courseMatch[1].trim();
    result.confidence += 0.4;
  }

  return result;
};

// 处理文本和图片
app.post('/process', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    const { text, method } = req.body;
    const file = req.file;

    if (!text && !file) {
      return res.status(400).json({
        success: false,
        message: '请提供文本或图片'
      });
    }

    // 验证处理方法
    if (method !== 'machine' && method !== 'api') {
      return res.status(400).json({
        success: false,
        message: '无效的处理方法'
      });
    }

    let content = text;
    
    // 如果有图片，使用OCR处理
    if (file) {
      const worker = await createWorker('chi_sim');
      const { data: { text: ocrText } } = await worker.recognize(file.path);
      await worker.terminate();
      content = ocrText;
    }

    let result;
    const now = new Date().toISOString();

    if (method === 'machine') {
      // 使用自然语言处理
      result = await processWithNLP(content);
    } else if (method === 'api') {
      // 获取用户的API密钥
      const user = await db.collection('users').findOne(
        { _id: new ObjectId(req.user.id) },
        { projection: { apiKeys: 1 } }
      );

      const provider = req.body.provider || 'openai';

      if (!user || !user.apiKeys || !user.apiKeys[provider]) {
        return res.status(400).json({
          success: false,
          message: `请先在管理页面设置${provider}的API密钥`
        });
      }

      // 使用用户存储的API密钥进行AI处理
      result = await processWithAI(content, provider, user.apiKeys[provider]);
    }

    // 添加处理时间和方法
    result.processedAt = now;
    result.provider = method === 'machine' ? 'machine' : req.body.provider;

    res.json({
      success: true,
      message: '处理成功',
      data: result
    });

  } catch (error) {
    console.error('处理错误:', error);
    res.status(500).json({
      success: false,
      message: '处理失败，请检查输入和API密钥是否正确',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// NLP处理函数
async function processWithNLP(content) {
  try {
    // 使用自然语言处理来提取信息
    const tokenizer = new natural.WordTokenizer();
    const tokens = tokenizer.tokenize(content);
    
    // 提取可能的日期信息
    const datePattern = /(\d{4}[-/年]\d{1,2}[-/月]\d{1,2}日?)|(\d{1,2}[-/月]\d{1,2}日?)/g;
    const dateMatches = content.match(datePattern);
    let dueDate = null;
    let dueDateConfidence = 0;
    let dueDateOriginal = null;

    if (dateMatches) {
      dueDateOriginal = dateMatches[0];
      // 简单的日期解析
      const dateStr = dueDateMatches[0]
        .replace(/年|月|日/g, '-')
        .replace(/\/$/, '');
      dueDate = new Date(dateStr);
      if (!isNaN(dueDate)) {
        dueDate = dueDate.toISOString();
        dueDateConfidence = 0.8;
      }
    }

    // 提取学科信息
    const subjects = ['语文', '数学', '英语', '物理', '化学', '生物', '历史', '地理', '政治'];
    let subject = '';
    let confidence = 0.3;

    for (const sub of subjects) {
      if (content.includes(sub)) {
        subject = sub;
        confidence = 0.8;
        break;
      }
    }

    // 提取课程信息
    const coursePattern = /课程[：:]\s*([^\n]+)/;
    const courseMatch = content.match(coursePattern);
    const course = courseMatch ? courseMatch[1].trim() : '';

    return {
      content,
      subject,
      course,
      dueDate,
      dueDateConfidence,
      dueDateOriginal,
      confidence,
      suggestions: []
    };
  } catch (error) {
    console.error('NLP处理错误:', error);
    throw new Error('文本处理失败');
  }
}

// AI API处理函数
async function processWithAI(content, provider, apiKey) {
  try {
    let result = {
      content,
      subject: '',
      course: '',
      dueDate: null,
      dueDateConfidence: 0,
      dueDateOriginal: null,
      confidence: 0.5,
      suggestions: []
    };

    const systemPrompt = "你是一个专门处理作业信息的AI助手。请从文本中提取以下信息：学科、课程、截止日期。如果发现作业描述不清晰或有改进空间，请提供改进建议。";
    const userPrompt = `请分析以下作业内容，并提取关键信息：
${content}

请按以下JSON格式返回结果（注意：所有字段都必须返回，如果没有相关信息则返回空值）：
{
  "subject": "学科名称",
  "course": "课程名称",
  "dueDate": "截止日期（YYYY-MM-DD格式）",
  "dueDateConfidence": "日期识别的置信度（0-1之间的小数）",
  "dueDateOriginal": "原始日期文本",
  "confidence": "整体识别的置信度（0-1之间的小数）",
  "suggestions": ["改进建议1", "改进建议2"]
}`;

    let aiResponse;
    
    // 根据不同的提供商调用相应的API
      switch (provider) {
      case 'deepseek':
        const deepseekResponse = await axios.post(
          'https://api.deepseek.com/v1/chat/completions',
          {
            model: "deepseek-chat",  // 使用默认的deepseek-chat模型
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: userPrompt }
            ],
            temperature: 0.7,
            max_tokens: 800,
            stream: false
          },
          {
            headers: {
              'Authorization': `Bearer ${apiKey}`,
              'Content-Type': 'application/json',
              'Accept': 'application/json'
            }
          }
        );

        try {
          const responseContent = deepseekResponse.data.choices[0].message.content;
          console.log('Deepseek原始响应:', responseContent);
          aiResponse = JSON.parse(responseContent);
        } catch (parseError) {
          console.error('Deepseek响应解析错误:', parseError);
          console.log('原始响应:', deepseekResponse.data);
          throw new Error('AI响应格式错误');
        }
          break;

      case 'doubao':
        const doubaoResponse = await axios.post(
          'https://api.doubao.com/api/chat/completion',
          {
            model: "doubao-chat",
            messages: [
              { role: "system", content: systemPrompt },
              { role: "user", content: userPrompt }
            ],
            temperature: 0.7,
            max_tokens: 800
          },
          {
            headers: {
              'Authorization': `Bearer ${apiKey}`,
              'Content-Type': 'application/json'
            }
          }
        );

        aiResponse = JSON.parse(doubaoResponse.data.choices[0].message.content);
          break;

        default:
        throw new Error('不支持的AI提供商');
    }

    // 验证并格式化AI响应
    if (aiResponse) {
      result = {
        ...result,
        subject: aiResponse.subject || '',
        course: aiResponse.course || '',
        dueDate: aiResponse.dueDate || null,
        dueDateConfidence: parseFloat(aiResponse.dueDateConfidence) || 0,
        dueDateOriginal: aiResponse.dueDateOriginal || null,
        confidence: parseFloat(aiResponse.confidence) || 0.5,
        suggestions: Array.isArray(aiResponse.suggestions) ? aiResponse.suggestions : []
      };
    }

    return result;
  } catch (error) {
    console.error('AI处理错误:', error);
    if (error.response) {
      console.error('API响应错误:', {
        status: error.response.status,
        data: error.response.data
      });
    }
    throw new Error(`AI处理失败: ${error.message}`);
  }
}

// 获取用户的处理历史
app.get('/results', authenticateToken, async (req, res) => {
  try {
    const results = await db.collection('results')
      .find({ userId: new ObjectId(req.user.id) })
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();

    // 格式化返回的数据
    const formattedResults = results.map(result => ({
      id: result._id,
      content: result.content,
      subject: result.subject,
      course: result.course,
      dueDate: result.dueDate,
      dueDateConfidence: result.dueDateConfidence,
      dueDateOriginal: result.dueDateOriginal,
      confidence: result.confidence,
      suggestions: result.suggestions,
      provider: result.provider,
      processedAt: result.processedAt,
      createdAt: result.createdAt,
      updatedAt: result.updatedAt
    }));

      res.json({
        success: true,
      data: formattedResults
    });
  } catch (error) {
    console.error('获取历史记录错误:', error);
    res.status(500).json({ 
      success: false,
      message: '获取历史记录失败' 
    });
  }
});

// 更新作业记录
app.put('/results/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const updateData = req.body;
    
    // 验证必要字段
    const { content, subject, course, dueDate } = updateData;
    if (!content) {
      return res.status(400).json({
        success: false,
        message: '内容不能为空'
      });
    }

    // 验证记录所有权
    const existingRecord = await db.collection('results').findOne({
      _id: new ObjectId(id),
      userId: new ObjectId(req.user.id)
    });

    if (!existingRecord) {
      return res.status(404).json({
        success: false,
        message: '记录不存在或无权访问'
      });
    }

    const now = new Date().toISOString();

    // 更新文档
    const result = await db.collection('results').updateOne(
      { 
        _id: new ObjectId(id),
        userId: new ObjectId(req.user.id)
      },
      { 
        $set: {
          content,
          subject: subject || '',
          course: course || '',
          dueDate: dueDate || null,
          dueDateConfidence: updateData.dueDateConfidence,
          dueDateOriginal: updateData.dueDateOriginal,
          confidence: updateData.confidence,
          suggestions: updateData.suggestions || [],
          provider: updateData.provider || existingRecord.provider,
          processedAt: updateData.processedAt || existingRecord.processedAt || now,
          updatedAt: now
        }
      }
    );

    if (result.matchedCount === 0) {
      throw new Error('更新失败');
    }

      res.json({
        success: true,
      message: '更新成功'
    });
  } catch (error) {
    console.error('更新错误:', error);
    res.status(500).json({
      success: false,
      message: '更新失败，请重试',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 删除作业记录
app.delete('/results/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // 验证记录所有权
    const existingRecord = await db.collection('results').findOne({
      _id: new ObjectId(id),
      userId: new ObjectId(req.user.id)
    });

    if (!existingRecord) {
      return res.status(404).json({
        success: false,
        message: '记录不存在或无权访问'
      });
    }

    // 删除文档
    const result = await db.collection('results').deleteOne({
      _id: new ObjectId(id),
      userId: new ObjectId(req.user.id)
    });

    if (result.deletedCount === 0) {
      throw new Error('删除失败');
    }

    res.json({
      success: true,
      message: '删除成功'
    });
  } catch (error) {
    console.error('删除错误:', error);
    res.status(500).json({
      success: false,
      message: '删除失败，请重试',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// 保存处理结果
app.post('/save', authenticateToken, async (req, res) => {
  try {
    console.log('保存请求开始，请求体:', JSON.stringify(req.body, null, 2));
    
    // 验证必要字段
    const { content } = req.body;
    if (!content) {
      console.log('内容为空，拒绝保存');
      return res.status(400).json({
        success: false,
        message: '内容不能为空'
      });
    }

    const now = new Date().toISOString();

    // 准备保存的文档
    const resultDoc = {
      userId: new ObjectId(req.user.id),
      content: req.body.content,
      subject: req.body.subject || '',
      course: req.body.course || '',
      dueDate: req.body.dueDate || null,
      dueDateConfidence: parseFloat(req.body.dueDateConfidence) || 0,
      dueDateOriginal: req.body.dueDateOriginal || '',
      confidence: parseFloat(req.body.confidence) || 0,
      suggestions: Array.isArray(req.body.suggestions) ? req.body.suggestions : [],
      provider: req.body.provider || 'machine',
      processedAt: req.body.processedAt || now,
      createdAt: now,
      updatedAt: now
    };

    console.log('准备保存的文档:', JSON.stringify(resultDoc, null, 2));

    // 检查是否存在相同内容的记录
    const existingRecord = await db.collection('results').findOne({
      userId: new ObjectId(req.user.id),
      content: content
    });

    if (existingRecord) {
      console.log('找到已存在的记录:', existingRecord._id.toString());
      return res.json({
        success: true,
        message: '记录已存在',
        data: {
          id: existingRecord._id,
          processedAt: existingRecord.processedAt,
          provider: existingRecord.provider
        }
      });
    }

    // 保存到数据库
    const result = await db.collection('results').insertOne(resultDoc);
    console.log('数据库插入结果:', result);

    if (!result.acknowledged) {
      console.error('保存失败: 数据库未确认插入');
      throw new Error('数据库插入未确认');
    }

    const savedRecord = await db.collection('results').findOne({
      _id: result.insertedId
    });
    console.log('已保存的记录:', savedRecord);

    res.json({
      success: true,
      message: '保存成功',
      data: {
        id: result.insertedId,
        processedAt: resultDoc.processedAt,
        provider: resultDoc.provider,
        content: resultDoc.content,
        subject: resultDoc.subject,
        course: resultDoc.course
      }
    });

  } catch (error) {
    console.error('保存错误:', error);
    console.error('错误详情:', {
      name: error.name,
      message: error.message,
      code: error.code,
      stack: error.stack
    });
    res.status(500).json({
      success: false,
      message: '保存失败，请重试',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`服务器运行在端口 ${PORT}`);
}); 