const express = require('express');
const app = express();

app.get('/calc', (req, res) => {
  const result = eval(req.query.expr);
  res.json({ result });
});
