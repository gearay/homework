app.get('/api/results', async (req, res) => {
  try {
    const userId = req.query.userId;
    if (!userId) {
      return res.status(400).json({ error: '缺少用户ID参数' });
    }

    const results = await Result.find({ userId })
      .select({
        content: 1,
        subject: 1,
        course: 1,
        dueDate: 1,
        dueDateConfidence: 1,
        dueDateOriginal: 1,
        confidence: 1,
        suggestions: 1,
        processedAt: 1,
        provider: 1,
        status: 1,
        isCompleted: 1,
        completedAt: 1,
        score: 1,
        difficulty: 1,
        timeSpent: 1,
        category: 1,
        createdAt: 1,
        updatedAt: 1
      })
      .sort({ createdAt: -1 });

    res.json(results);
  } catch (error) {
    console.error('获取作业记录失败:', error);
    res.status(500).json({ error: '获取作业记录失败' });
  }
}); 