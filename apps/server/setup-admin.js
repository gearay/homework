import { MongoClient } from 'mongodb';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';

dotenv.config();

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'admin123'; // 默认密码，建议首次登录后立即修改

async function setupAdmin() {
  const mongoClient = new MongoClient(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017');
  
  try {
    await mongoClient.connect();
    console.log('已连接到MongoDB');
    
    const db = mongoClient.db('homework_system');
    
    // 检查管理员是否已存在
    const existingAdmin = await db.collection('users').findOne({ isAdmin: true });
    
    if (existingAdmin) {
      console.log('管理员账户已存在，跳过创建');
      return;
    }
    
    // 创建管理员账户
    const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
    const adminUser = {
      username: ADMIN_USERNAME,
      password: hashedPassword,
      isAdmin: true,
      status: 'active',
      apiKeys: {
        openai: '',
        deepseek: '',
        doubao: ''
      },
      createdAt: new Date(),
      lastLoginAt: null
    };
    
    await db.collection('users').insertOne(adminUser);
    console.log('管理员账户创建成功');
    console.log('用户名:', ADMIN_USERNAME);
    console.log('密码:', ADMIN_PASSWORD);
    console.log('请在首次登录后立即修改密码');
    
  } catch (error) {
    console.error('创建管理员账户失败:', error);
  } finally {
    await mongoClient.close();
  }
}

setupAdmin().catch(console.error); 