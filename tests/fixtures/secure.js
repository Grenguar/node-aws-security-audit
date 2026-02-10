// Secure fixtures — these should NOT be flagged

// Proper parameterized query
const user = await User.findOne({ _id: req.params.id, owner: req.user._id });

// Environment variable for secrets
const JWT_SECRET = process.env.JWT_SECRET;

// Strong hashing
const hash = crypto.createHash('sha256').update(data).digest('hex');

// bcrypt
const hashed = await bcrypt.hash(password, 12);

// execFile instead of exec
const { execFile } = require('child_process');
execFile('/usr/bin/ls', [dir]);

// Safe Buffer usage
const buf = Buffer.alloc(100);
const buf2 = Buffer.from(data);

// WHATWG URL API
const url = new URL(input);

// URLSearchParams
const params = new URLSearchParams(input);
