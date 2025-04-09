require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const users = require('./users');
const authenticateToken = require('./auth');
const app = express();

app.use(express.json());

app.post('/signup', async (req, res) => {
  const { username, password } = req.body;
  const exists = users.find(user => user.username === username);
  if (exists) return res.status(400).json({ message: 'User already exists' });

  const hashed = await bcrypt.hash(password, 10);
  users.push({ username, password: hashed });
  res.status(201).json({ message: 'User registered' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);
  if (!user) return res.status(400).json({ message: 'Username not found' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(400).json({ message: 'Invalid password' });

  const token = jwt.sign({ username }, process.env.JWT_SECRET, { expiresIn: '1h' });
  res.status(200).json({ token });
});

app.get('/profile', authenticateToken, (req, res) => {
  res.json({ message: `Welcome ${req.user.username}!` });
});

app.listen(8083, () => console.log('Server running on http://localhost:8083'));
