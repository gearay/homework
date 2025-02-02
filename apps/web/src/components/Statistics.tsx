import React, { useEffect, useState } from 'react';
import { API_BASE_URL } from '../config';

interface StatisticsData {
  overview: {
    totalHomework: number;
    subjectCount: number;
    averageConfidence: number;
    completedCount: number;
    completionRate: number;
    averageScore: number;
  };
  dailyTrend: Array<{
    _id: string;
    date: string;
    count: number;
    completedCount: number;
    averageConfidence: number;
  }>;
  subjectStats: Array<{
    subject: string;
    count: number;
    completedCount: number;
    completionRate: number;
    averageConfidence: number;
    averageScore: number;
  }>;
  difficultyStats: Array<{
    difficulty: string;
    count: number;
    completedCount: number;
    completionRate: number;
    averageScore: number;
  }>;
}

const Statistics: React.FC = () => {
  const [statistics, setStatistics] = useState<StatisticsData | null>(null);
  const [error, setError] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const fetchStatistics = async () => {
      try {
        const response = await fetch(`${API_BASE_URL}/api/statistics`, {
          headers: {
            'Authorization': `Bearer ${localStorage.getItem('token')}`
          }
        });

        if (!response.ok) {
          throw new Error('获取统计数据失败');
        }

        const data = await response.json();
        if (data.success) {
          setStatistics(data.data);
        } else {
          throw new Error(data.message || '获取统计数据失败');
        }
      } catch (error) {
        setError(error instanceof Error ? error.message : '获取统计数据失败');
      } finally {
        setLoading(false);
      }
    };

    fetchStatistics();
  }, []);

  if (loading) {
    return <div className="loading">加载中...</div>;
  }

  if (error) {
    return <div className="error-message">{error}</div>;
  }

  if (!statistics) {
    return <div className="empty-message">暂无统计数据</div>;
  }

  return (
    <div className="statistics-container">
      <div className="statistics-section overview">
        <h3>总览</h3>
        <div className="stats-grid">
          <div className="stat-item">
            <div className="stat-value">{statistics.overview.totalHomework}</div>
            <div className="stat-label">作业总数</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">{statistics.overview.completedCount}</div>
            <div className="stat-label">已完成数量</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">{statistics.overview.completionRate}%</div>
            <div className="stat-label">完成率</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">{statistics.overview.subjectCount}</div>
            <div className="stat-label">学科数量</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">{statistics.overview.averageScore || '暂无'}</div>
            <div className="stat-label">平均分数</div>
          </div>
          <div className="stat-item">
            <div className="stat-value">{statistics.overview.averageConfidence}%</div>
            <div className="stat-label">平均置信度</div>
          </div>
        </div>
      </div>

      <div className="statistics-section subjects">
        <h3>学科统计</h3>
        <div className="subject-stats">
          <table className="stats-table">
            <thead>
              <tr>
                <th>学科</th>
                <th>作业数量</th>
                <th>已完成</th>
                <th>完成率</th>
                <th>平均分数</th>
                <th>平均置信度</th>
              </tr>
            </thead>
            <tbody>
              {statistics.subjectStats.map((subject) => (
                <tr key={subject.subject}>
                  <td>{subject.subject}</td>
                  <td>{subject.count}</td>
                  <td>{subject.completedCount}</td>
                  <td>{subject.completionRate}%</td>
                  <td>{subject.averageScore || '暂无'}</td>
                  <td>{subject.averageConfidence}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="statistics-section difficulty">
        <h3>难度分布</h3>
        <div className="difficulty-stats">
          <table className="stats-table">
            <thead>
              <tr>
                <th>难度</th>
                <th>作业数量</th>
                <th>已完成</th>
                <th>完成率</th>
                <th>平均分数</th>
              </tr>
            </thead>
            <tbody>
              {statistics.difficultyStats.map((diff) => (
                <tr key={diff.difficulty}>
                  <td>{diff.difficulty}</td>
                  <td>{diff.count}</td>
                  <td>{diff.completedCount}</td>
                  <td>{diff.completionRate}%</td>
                  <td>{diff.averageScore || '暂无'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="statistics-section trend">
        <h3>近7天趋势</h3>
        <div className="daily-trend">
          <table className="stats-table">
            <thead>
              <tr>
                <th>日期</th>
                <th>作业数量</th>
                <th>已完成</th>
                <th>平均置信度</th>
              </tr>
            </thead>
            <tbody>
              {statistics.dailyTrend.map((day) => (
                <tr key={day._id}>
                  <td>{day.date}</td>
                  <td>{day.count}</td>
                  <td>{day.completedCount}</td>
                  <td>{day.averageConfidence}%</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Statistics; 