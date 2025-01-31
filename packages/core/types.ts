import { ObjectId } from 'mongodb';

// 作业数据模型
export interface Assignment {
  _id: ObjectId;
  raw_text: string;  // 原始输入文本
  processed_data: {
    subjects: string[];  // 学科标签
    courses: string[];   // 课程标签
    deadlines: Date[];   // 时间节点
    metadata: Record<string, any>; // 扩展元数据
  };
  analysis_tags: {   
    difficulty?: number;
    estimated_time?: number;
    priority?: 'high' | 'medium' | 'low';
  };
  version: number;     // 数据版本号
  created_at: Date;
  updated_at: Date;
}

// LLM分析结果接口
export interface AnalysisResult {
  subjects: string[];
  courses: string[];
  deadlines: Date[];
  tags: {
    difficulty: number;
    estimated_time: number;
    priority: 'high' | 'medium' | 'low';
  };
  metadata: Record<string, any>;
}

// LLM提供者接口
export interface LLMProvider {
  id: string;
  name: string;
  analyze(text: string, options: {
    lang?: 'zh' | 'en';
    model?: string;
  }): Promise<AnalysisResult>;
}

// OCR处理结果接口
export interface OCRResult {
  text: string;
  confidence: number;
  language?: string;
  boundingBoxes?: Array<{
    x: number;
    y: number;
    width: number;
    height: number;
    text: string;
  }>;
}

// API响应接口
export interface APIResponse<T> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
  };
  meta?: {
    page?: number;
    limit?: number;
    total?: number;
  };
} 