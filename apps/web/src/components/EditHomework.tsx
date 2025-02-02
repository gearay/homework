import React, { useState } from 'react';

interface EditHomeworkProps {
  homework: {
    id?: string;
    content: string;
    subject: string;
    course: string;
    dueDate: string;
    dueDateConfidence?: number;
    dueDateOriginal?: string;
    confidence?: number;
    suggestions?: string[];
    processedAt?: string;
    provider?: string;
    isCompleted: boolean;
    completedAt: string | null;
    score: number | null;
    difficulty: string;
    timeSpent: number | null;
  };
  onSave: (updatedHomework: any) => void;
  onCancel: () => void;
}

const EditHomework: React.FC<EditHomeworkProps> = ({ homework, onSave, onCancel }) => {
  const [formData, setFormData] = useState({
    content: homework.content || '',
    subject: homework.subject || '',
    course: homework.course || '',
    dueDate: homework.dueDate ? new Date(homework.dueDate).toISOString().split('T')[0] : '',
    difficulty: homework.difficulty || 'medium',
    isCompleted: homework.isCompleted || false,
    score: homework.score !== null ? homework.score : '',
    timeSpent: homework.timeSpent !== null ? homework.timeSpent : ''
  });

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value, type } = e.target;
    if (type === 'checkbox') {
      const checkbox = e.target as HTMLInputElement;
      setFormData(prev => ({
        ...prev,
        [name]: checkbox.checked
      }));
    } else {
      setFormData(prev => ({
        ...prev,
        [name]: value
      }));
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    onSave({
      ...homework,
      ...formData,
      score: formData.score === '' ? null : Number(formData.score),
      timeSpent: formData.timeSpent === '' ? null : Number(formData.timeSpent),
      completedAt: formData.isCompleted ? new Date().toISOString() : null
    });
  };

  return (
    <div className="edit-homework-form">
      <h2>编辑作业</h2>
      <form onSubmit={handleSubmit}>
        <div className="form-group">
          <label>作业内容:</label>
          <textarea
            name="content"
            value={formData.content}
            onChange={handleChange}
            required
          />
        </div>

        <div className="form-group">
          <label>学科:</label>
          <input
            type="text"
            name="subject"
            value={formData.subject}
            onChange={handleChange}
            required
          />
        </div>

        <div className="form-group">
          <label>课程:</label>
          <input
            type="text"
            name="course"
            value={formData.course}
            onChange={handleChange}
            required
          />
        </div>

        <div className="form-group">
          <label>截止日期:</label>
          <input
            type="date"
            name="dueDate"
            value={formData.dueDate}
            onChange={handleChange}
          />
        </div>

        <div className="form-group">
          <label>难度:</label>
          <select
            name="difficulty"
            value={formData.difficulty}
            onChange={handleChange}
          >
            <option value="easy">简单</option>
            <option value="medium">中等</option>
            <option value="hard">困难</option>
          </select>
        </div>

        <div className="form-group checkbox">
          <label>
            <input
              type="checkbox"
              name="isCompleted"
              checked={formData.isCompleted}
              onChange={handleChange}
            />
            已完成
          </label>
        </div>

        <div className="form-group">
          <label>分数:</label>
          <input
            type="number"
            name="score"
            value={formData.score}
            onChange={handleChange}
            min="0"
            max="100"
            placeholder="输入0-100的分数"
          />
        </div>

        <div className="form-group">
          <label>用时(分钟):</label>
          <input
            type="number"
            name="timeSpent"
            value={formData.timeSpent}
            onChange={handleChange}
            min="0"
            placeholder="输入完成用时"
          />
        </div>

        <div className="form-actions">
          <button type="submit" className="save-button">保存</button>
          <button type="button" onClick={onCancel} className="cancel-button">取消</button>
        </div>
      </form>
    </div>
  );
};

export default EditHomework; 