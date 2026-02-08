const https = require("https");
const fs = require("fs");
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();

const allowedOrigins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
];

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (e.g., curl, server-to-server)
    if (!origin) {
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("Not allowed by CORS"));
  },
  credentials: false,
}));

app.use(express.static("public"));
app.use(express.json({ limit: '10mb' }));

// --- IN-MEMORY DATABASE ---
const users = new Map();

// Initialize default user
(async () => {
  const hashedPassword = await bcrypt.hash('password123', 10);
  users.set('student1', {
    username: 'student1',
    password: hashedPassword,
    role: 'student',
    details: {
      name: 'John Doe',
      id: 'U2024001',
      gpa: '3.8',
      major: 'Computer Science',
    },
    createdAt: new Date().toISOString()
  });
})();

// --- SECURITY MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Access denied" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid or expired token" });
    req.user = user;
    next();
  });
};

// --- VALIDATION ---
const validateRegistration = (req, res, next) => {
  const { username, password, name, id } = req.body;
  
  if (!username || !password || !name || !id) {
    return res.status(400).json({ error: "All fields are required" });
  }
  
  if (username.length < 3 || username.length > 20) {
    return res.status(400).json({ error: "Username must be 3-20 characters" });
  }
  
  if (password.length < 6) {
    return res.status(400).json({ error: "Password must be at least 6 characters" });
  }
  
  if (!/^[a-zA-Z0-9]+$/.test(username)) {
    return res.status(400).json({ error: "Username can only contain letters and numbers" });
  }
  
  if (users.has(username)) {
    return res.status(400).json({ error: "Username already exists" });
  }
  
  next();
};

const validateLogin = (req, res, next) => {
  const { username, password } = req.body;
  
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }
  
  next();
};

// --- ROUTES ---

// Register new account
app.post("/api/register", validateRegistration, async (req, res) => {
  const { username, password, name, id } = req.body;
  
  const hashedPassword = await bcrypt.hash(password, 10);
  
  users.set(username, {
    username,
    password: hashedPassword,
    role: 'student',
    details: {
      name,
      id,
      gpa: '0.0',
      major: 'Undeclared',
    },
    createdAt: new Date().toISOString()
  });
  
  console.log(`[REGISTRATION]: New user '${username}' registered`);
  
  res.json({ message: "Account created successfully" });
});

// Login
app.post("/api/login", validateLogin, async (req, res) => {
  const { username, password } = req.body;
  const user = users.get(username);
  
  if (!user) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  
  const isValid = await bcrypt.compare(password, user.password);
  
  if (!isValid) {
    return res.status(401).json({ error: "Invalid credentials" });
  }
  
  const token = jwt.sign(
    { username: user.username, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
  );
  
  res.json({ 
    accessToken: token,
    user: {
      username: user.username,
      name: user.details.name,
      role: user.role
    }
  });
});

// Get profile
app.get("/api/profile", authenticateToken, (req, res) => {
  const user = users.get(req.user.username);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  
  res.json(user.details);
});

// Update password
app.post("/api/change-password", authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const user = users.get(req.user.username);
  
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }
  
  const isValid = await bcrypt.compare(currentPassword, user.password);
  
  if (!isValid) {
    return res.status(401).json({ error: "Current password is incorrect" });
  }
  
  if (newPassword.length < 6) {
    return res.status(400).json({ error: "New password must be at least 6 characters" });
  }
  
  user.password = await bcrypt.hash(newPassword, 10);
  
  console.log(`[SECURITY]: Password changed for user '${user.username}'`);
  
  res.json({ message: "Password updated successfully" });
});

// Check username availability
app.get("/api/check-username/:username", (req, res) => {
  const available = !users.has(req.params.username);
  res.json({ available });
});

// --- ERROR HANDLING ---
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Internal server error" });
});

// --- SERVER ---
const options = {
  key: fs.readFileSync("localhost+1-key.pem"),
  cert: fs.readFileSync("localhost+1.pem"),
};

https.createServer(options, app).listen(3000, () => {
  console.log("University Portal running at https://localhost:3000");
  console.log("Default login: student1 / password123");
});
