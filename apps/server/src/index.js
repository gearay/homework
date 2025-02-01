import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { createWorker } from 'tesseract.js';
import natural from 'natural';
import { MongoClient, ObjectId } from 'mongodb';
import dotenv from 'dotenv';
import path from 'path';
import OpenAI from 'openai';
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
    await db.collection('results').createIndex({ userId: 1 });
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
      apiKeys: {
        openai: '',
        deepseek: '',
        doubao: ''
      },
      createdAt: new Date()
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
    
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: '用户名或密码错误' 
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

    // 生成JWT令牌
    const token = jwt.sign(
      { id: user._id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    // 返回用户信息和API密钥
    res.json({
      success: true,
      token,
      user: {
        username: user.username,
        apiKeys: user.apiKeys
      }
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
    
    // 验证提供商
    const validProviders = Object.values(LLM_PROVIDERS);
    if (!validProviders.includes(provider)) {
      return res.status(400).json({ message: '不支持的LLM提供商' });
    }

    const result = await db.collection('users').updateOne(
      { _id: new ObjectId(req.user.id) },
      { $set: { [`apiKeys.${provider}`]: apiKey } }
    );

    if (result.matchedCount === 0) {
      return res.status(404).json({ message: '用户不存在' });
    }

    res.json({ message: 'API密钥更新成功' });
  } catch (error) {
    console.error('更新API密钥错误:', error);
    res.status(500).json({ message: '更新API密钥失败' });
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

// 处理文本请求
app.post('/process', authenticateToken, upload.single('file'), async (req, res) => {
  try {
    let text = req.body.text;
    const method = req.body.method;
    const provider = req.body.provider;

    // 验证处理方法
    if (method !== 'nlp' && method !== 'api') {
      throw new Error('无效的处理方法');
    }

    // 如果是API处理方法，验证提供商并获取API密钥
    if (method === 'api') {
      // 验证提供商
      const validProviders = Object.values(LLM_PROVIDERS);
      if (!validProviders.includes(provider)) {
        throw new Error('不支持的LLM提供商');
      }

      // 获取用户的API密钥
      const user = await db.collection('users').findOne(
        { _id: new ObjectId(req.user.id) },
        { projection: { apiKeys: 1 } }
      );

      if (!user || !user.apiKeys || !user.apiKeys[provider]) {
        throw new Error(`请先设置${provider}的API密钥`);
      }

      // 使用用户存储的API密钥
      const apiKey = user.apiKeys[provider];

      if (!text && !req.file) {
        throw new Error('请提供文本或图片');
      }

      // 处理文本
      let result;
      switch (provider) {
        case LLM_PROVIDERS.OPENAI:
          result = await processWithGPT(text, apiKey);
          break;
        case LLM_PROVIDERS.DEEPSEEK:
          result = await processWithDeepseek(text, apiKey);
          break;
        case LLM_PROVIDERS.DOUBAO:
          result = await processWithDoubao(text, apiKey);
          break;
        default:
          throw new Error('不支持的LLM提供商');
      }

      // 添加处理时间戳和提供商信息
      result.processedAt = new Date().toISOString();
      result.provider = provider;

      // 保存处理结果
      const resultDoc = {
        userId: new ObjectId(req.user.id),
        content: text,
        processedResult: result,
        createdAt: new Date()
      };

      await db.collection('results').insertOne(resultDoc);

      res.json({
        success: true,
        data: result,
        message: '处理成功'
      });
    } else {
      // NLP处理
      const result = processText(text);
      result.processedAt = new Date().toISOString();
      result.provider = 'nlp';

      const resultDoc = {
        userId: new ObjectId(req.user.id),
        content: text,
        processedResult: result,
        createdAt: new Date()
      };

      await db.collection('results').insertOne(resultDoc);

      res.json({
        success: true,
        data: result,
        message: '处理成功'
      });
    }
  } catch (error) {
    console.error('处理错误:', error);
    res.status(500).json({
      success: false,
      error: error.message,
      message: '处理失败，请检查输入和API密钥是否正确'
    });
  }
});

// 获取用户的处理历史
app.get('/results', authenticateToken, async (req, res) => {
  try {
    const results = await db.collection('results')
      .find({ userId: new ObjectId(req.user.id) })
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();

    res.json(results);
  } catch (error) {
    console.error('获取历史记录错误:', error);
    res.status(500).json({ message: '获取历史记录失败' });
  }
});

// 保存处理结果
app.post('/save', authenticateToken, async (req, res) => {
  try {
    console.log('保存请求:', req.body);
    
    // 验证必要字段
    const { content, subject, course, dueDate } = req.body;
    if (!content) {
      return res.status(400).json({
        success: false,
        message: '内容不能为空'
      });
    }

    // 创建保存文档
    const resultDoc = {
      userId: new ObjectId(req.user.id),
      content,
      subject: subject || '',
      course: course || '',
      dueDate: dueDate || null,
      dueDateConfidence: req.body.dueDateConfidence,
      dueDateOriginal: req.body.dueDateOriginal,
      confidence: req.body.confidence,
      suggestions: req.body.suggestions || [],
      provider: req.body.provider,
      processedAt: req.body.processedAt || new Date().toISOString(),
      createdAt: new Date(),
      updatedAt: new Date()
    };

    // 保存到数据库
    const result = await db.collection('results').insertOne(resultDoc);
    console.log('保存结果:', result);

    if (result.acknowledged) {
      res.json({
        success: true,
        message: '保存成功',
        data: {
          id: result.insertedId
        }
      });
    } else {
      throw new Error('保存失败');
    }
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