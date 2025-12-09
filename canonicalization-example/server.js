// server.js
const express = require('express');
const path = require('path');
const fs = require('fs');
const { body, validationResult } = require('express-validator');
//const ROOT = "/var/www/";
const ROOT = path.resolve(__dirname);

const app = express();
app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const BASE_DIR = path.resolve(__dirname, 'files');
if (!fs.existsSync(BASE_DIR)) fs.mkdirSync(BASE_DIR, { recursive: true });

// helper to canonicalize and check
function resolveSafe(baseDir, userInput) {
  try {
    userInput = decodeURIComponent(userInput);
  } catch (e) {}
  return path.resolve(baseDir, userInput);
}

// set up rate limiter: maximum of five requests per minute
var RateLimit = require('express-rate-limit');
var limiter = RateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per windowMs
});

// apply rate limiter to all requests
app.use(limiter);

// Secure route
app.post(
  '/read',
  body('filename')
    .exists().withMessage('filename required')
    .bail()
    .isString()
    .trim()
    .notEmpty().withMessage('filename must not be empty')
    .custom(value => {
      if (value.includes('\0')) throw new Error('null byte not allowed');
      return true;
    }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    const filename = req.body.filename;
    const normalized = resolveSafe(BASE_DIR, filename);
    if (!normalized.startsWith(BASE_DIR + path.sep)) {
      return res.status(403).json({ error: 'Path traversal detected' });
    }
    if (!fs.existsSync(normalized)) return res.status(404).json({ error: 'File not found' });

    const content = fs.readFileSync(normalized, 'utf8');
    res.json({ path: normalized, content });
  }
);

// Vulnerable route (demo)
app.post('/read-no-validate', (req, res) => {
    const filename = req.body.filename || ''; //filename = user input or null 
    
    // 1. Determine the intended absolute path
    const candidatePath = path.resolve(BASE_DIR, filename);

    // 2. Resolve canonical path (resolves symlinks) and check against ROOT
    // CRITICAL FIX: The check must happen *after* resolving the path.
    let joined;
    try {
        // Use fs.realpathSync to resolve ALL symbolic links
        joined = fs.realpathSync(candidatePath); 
    } catch (e) {
        // If realpathSync throws an error (e.g., file doesn't exist or permissions issue)
        return res.status(404).json({ error: 'File not found' });
    }
  
    if (!joined.startsWith(ROOT)) {  //checking that path starts w/ root 
        res.statusCode = 403;
        res.end('Access denied.');
        return;
    }
  
    const content = fs.readFileSync(joined, 'utf8'); //safely reading the file 
    res.json({ path: joined, content });
});

// Helper route for samples
app.post('/setup-sample', (req, res) => {
  const samples = {
    'hello.txt': 'Hello from safe file!\n',
    'notes/readme.md': '# Readme\nSample readme file'
  };
  Object.keys(samples).forEach(k => {
    const p = path.resolve(BASE_DIR, k);
    const d = path.dirname(p);
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
    fs.writeFileSync(p, samples[k], 'utf8');
  });
  res.json({ ok: true, base: BASE_DIR });
});

// Only listen when run directly (not when imported by tests)
if (require.main === module) {
  const port = process.env.PORT || 4000;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}

module.exports = app;
