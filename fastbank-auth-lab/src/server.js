const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
// bcrypt is installed but NOT used in the vulnerable baseline:
const bcrypt = require("bcrypt");

//const app = express();
const PORT = 3001;

const app = require("express")(),
  cookieParser = require("cookie-parser"),
  bodyParser = require("body-parser"),
  csrf = require('lusca').csrf;


app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));
app.use(csrf());

/**
 * VULNERABLE FAKE USER DB
 * For simplicity, we start with a single user whose password is "password123".
 * In the vulnerable version, we hash with a fast hash (SHA-256-like).
 */
const users = [
  {
    id: 1,
    username: "student",
    // VULNERABLE: fast hash without salt
    passwordHash: fastHash("password123") // students must replace this scheme with bcrypt
  }
];

// In-memory session store
const sessions = {}; // token -> { userId }

/**
 * VULNERABLE FAST HASH FUNCTION
 * Students MUST STOP using this and replace logic with bcrypt.
 */
function fastHash(password, salt) {
  var hashed = bcrypt.hashSync(password, salt); // GOOD
  return hashed;
}

// Helper: find user by username
function findUser(username) {
  return users.find((u) => u.username === username);
}

// Home API just to show who is logged in
app.get("/api/me", (req, res) => {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }
  const session = sessions[token];
  const user = users.find((u) => u.id === session.userId);
  res.json({ authenticated: true, username: user.username });
});

/**
 * VULNERABLE LOGIN ENDPOINT
 * - Uses fastHash instead of bcrypt
 * - Error messages leak whether username exists
 * - Session token is simple and predictable
 * - Cookie lacks security flags
 */
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);

  if (!user) {
    // VULNERABLE: username enumeration via message
    return res
      .status(401)
      .json({ success: false, message: "Unknown username" });
  }

  const candidateHash = fastHash(password);
  if (candidateHash !== user.passwordHash) {
    return res
      .status(401)
      .json({ success: false, message: "Wrong password" });
  }

  // VULNERABLE: predictable token
  const token = username + "-" + Date.now();

  // VULNERABLE: session stored without expiration
  sessions[token] = { userId: user.id };

  // VULNERABLE: cookie without httpOnly, secure, sameSite
  res.cookie("session", token, {
    // students must add: httpOnly: true, secure: true, sameSite: "lax"
  });

  // Client-side JS (login.html) will store this token in localStorage (vulnerable)
  res.json({ success: true, token });
});

app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) {
    delete sessions[token];
  }
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running at http://localhost:${PORT}`);
});
