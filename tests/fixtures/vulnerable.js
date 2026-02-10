// Test fixtures — each line should trigger a specific grep pattern

// A01: Broken Access Control — IDOR
app.get('/api/users/:id', async (req, res) => {
  const user = await User.findById(req.params.id);
  res.json(user);
});

// A02: Cryptographic Failures — hardcoded secret
const JWT_SECRET = 'my-hardcoded-secret-key';

// A02: Weak hashing
const hash = crypto.createHash('md5').update(password).digest('hex');

// A03: Injection — eval
const result = eval(req.body.expression);

// A03: SQL injection via template literal
const query = `SELECT * FROM users WHERE id = ${req.params.id}`;

// A03: Command injection
const { exec } = require('child_process');
exec('ls ' + req.query.path);

// A06: Vulnerable component
const serialize = require('node-serialize');

// A07: Auth — weak JWT
jwt.verify(token, secret, { algorithms: ['none'] });

// A09: Logging — full request body
console.log(req.body);

// A10: SSRF
fetch(req.query.url);

// Built-in: vm module
const vm = require('vm');
vm.runInNewContext(userCode);

// Built-in: Buffer constructor
const buf = new Buffer(100);

// Built-in: url.parse
const url = require('url');
const parsed = url.parse(input);

// Built-in: querystring
const qs = require('querystring');
