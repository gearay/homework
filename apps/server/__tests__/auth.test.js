import { MongoClient } from 'mongodb';
import { MongoMemoryServer } from 'mongodb-memory-server';
import request from 'supertest';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import express from 'express';
import cors from 'cors';

let mongoServer;
let mongoClient;
let db;
let app;

beforeAll(async () => {
  // 启动内存数据库
  mongoServer = await MongoMemoryServer.create();
  const mongoUri = mongoServer.getUri();
  
  // 连接到内存数据库
  mongoClient = new MongoClient(mongoUri);
  await mongoClient.connect();
  db = mongoClient.db('test');
  
  // 创建必要的索引
  await db.collection('users').createIndex({ username: 1 }, { unique: true });
  
  // 创建Express应用
  app = express();
  app.use(cors());
  app.use(express.json());
  
  // 注册路由
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
      
      if (error.code === 11000) {
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

  app.post('/auth/login', async (req, res) => {
    try {
      const { username, password } = req.body;

      const user = await db.collection('users').findOne({ username });
      if (!user) {
        return res.status(401).json({ 
          success: false,
          message: '用户名或密码错误' 
        });
      }

      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) {
        return res.status(401).json({ 
          success: false,
          message: '用户名或密码错误' 
        });
      }

      const token = jwt.sign(
        { id: user._id, username: user.username },
        process.env.JWT_SECRET || 'test_secret',
        { expiresIn: '24h' }
      );

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
      res.status(500).json({ 
        success: false,
        message: '登录失败' 
      });
    }
  });
});

afterAll(async () => {
  await mongoClient.close();
  await mongoServer.stop();
});

describe('用户认证测试', () => {
  beforeEach(async () => {
    // 清空用户集合
    await db.collection('users').deleteMany({});
  });

  describe('注册功能', () => {
    it('应该成功注册新用户', async () => {
      const response = await request(app)
        .post('/auth/register')
        .send({
          username: 'testuser',
          password: 'password123'
        });

      expect(response.status).toBe(201);
      expect(response.body.success).toBe(true);
      expect(response.body.message).toBe('注册成功');

      // 验证用户是否已保存到数据库
      const user = await db.collection('users').findOne({ username: 'testuser' });
      expect(user).toBeTruthy();
      expect(user.username).toBe('testuser');
      expect(await bcrypt.compare('password123', user.password)).toBe(true);
    });

    it('应该拒绝重复的用户名', async () => {
      // 先创建一个用户
      await request(app)
        .post('/auth/register')
        .send({
          username: 'testuser',
          password: 'password123'
        });

      // 尝试创建同名用户
      const response = await request(app)
        .post('/auth/register')
        .send({
          username: 'testuser',
          password: 'password456'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('用户名已存在');
    });

    it('应该验证用户名长度', async () => {
      const response = await request(app)
        .post('/auth/register')
        .send({
          username: 'ab',
          password: 'password123'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('用户名长度必须在3-20个字符之间');
    });

    it('应该验证密码长度', async () => {
      const response = await request(app)
        .post('/auth/register')
        .send({
          username: 'testuser',
          password: '12345'
        });

      expect(response.status).toBe(400);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('密码长度不能少于6个字符');
    });
  });

  describe('登录功能', () => {
    beforeEach(async () => {
      // 创建测试用户
      await request(app)
        .post('/auth/register')
        .send({
          username: 'testuser',
          password: 'password123'
        });
    });

    it('应该成功登录已存在的用户', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({
          username: 'testuser',
          password: 'password123'
        });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
      expect(response.body.token).toBeTruthy();
      expect(response.body.user.username).toBe('testuser');
    });

    it('应该拒绝错误的密码', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({
          username: 'testuser',
          password: 'wrongpassword'
        });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('用户名或密码错误');
    });

    it('应该拒绝不存在的用户名', async () => {
      const response = await request(app)
        .post('/auth/login')
        .send({
          username: 'nonexistentuser',
          password: 'password123'
        });

      expect(response.status).toBe(401);
      expect(response.body.success).toBe(false);
      expect(response.body.message).toBe('用户名或密码错误');
    });
  });
}); 