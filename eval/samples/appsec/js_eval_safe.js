const express = require('express');
const app = express();

app.get('/calc', (req, res) => {
  const a = Number(req.query.a);
  const b = Number(req.query.b);
  res.json({ result: a + b });
});
