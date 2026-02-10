const express = require('express');
const crypto = require('crypto');
const { exec } = require('child_process'); // VULN: command-injection risk
const jwt = require('jsonwebtoken');
const serialize = require('node-serialize'); // VULN: known RCE package

const app = express();

// VULN: no helmet middleware — missing security headers
// VULN: no rate limiting — brute-force / DoS risk

// VULN: no body size limit — potential DoS via large payloads
app.use(express.json());

// VULN: permissive CORS — any origin can make requests
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', '*');
  next();
});

// VULN: static files served without dotfiles:'deny' — exposes .env, .git, etc.
app.use(express.static('public'));

// VULN: hardcoded JWT secret
const JWT_SECRET = 'super-secret-key-123';

// Mongoose model (assume connected elsewhere)
const mongoose = require('mongoose');
const User = mongoose.model('User', new mongoose.Schema({ name: String, password: String }));

app.post('/login', async (req, res) => {
  // VULN: PII logging — logs full request body including passwords
  console.log(req.body);

  const { name, password } = req.body;

  // VULN: weak hashing — MD5 is cryptographically broken
  const hash = crypto.createHash('md5').update(password).digest('hex');

  // VULN: NoSQL injection via $where operator with string concatenation
  const user = await User.find({ $where: 'this.name === "' + name + '"' });

  if (user.length && user[0].password === hash) {
    const token = jwt.sign({ name }, JWT_SECRET);
    return res.json({ token });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

app.get('/profile', (req, res) => {
  // VULN: eval with user input — arbitrary code execution
  const filter = eval('(' + req.query.filter + ')');
  res.json({ filter });
});

app.post('/deserialize', (req, res) => {
  // VULN: unsafe deserialization — RCE via node-serialize
  const obj = serialize.unserialize(req.body.data);
  res.json(obj);
});

app.get('/exec', (req, res) => {
  // VULN: command injection — unsanitised user input passed to shell
  exec('echo ' + req.query.msg, (err, stdout) => {
    res.send(stdout);
  });
});

// VULN: verbose error handler — leaks stack traces to clients
app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message, stack: err.stack });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Listening on ${PORT}`));
