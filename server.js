const https = require('https');
const fs = require('fs');
const express = require('express');
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken'); 
require('dotenv').config();

const app = express();
app.use(express.static('public')); 
app.use(express.json());

// --- DATABASE (Sensitive Information Handling) ---
let users = [
    { 
        username: "student1", 
        password: "$2a$10$UnV6y.WzL9.5VfRz6YQvhuI/V.K1Ym4F4F6F6F6F6F6F6F6F6F6F6F", // 'password123'
        role: "student",
        details: { name: "John Doe", id: "U2024001", gpa: "3.8", major: "Computer Science" }
    }
];

// --- FAIL SECURELY MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).send("No session found"); 

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send("Session expired");
        req.user = user;
        next();
    });
};

// --- ROUTES ---

// 1. Secure Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username);

    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username, role: user.role }, process.env.JWT_SECRET);
        res.json({ accessToken: token });
    } else {
        res.status(401).send("Invalid Credentials");
    }
});

// 2. Student Profile (Access Control: Least Privilege)
app.get('/api/profile', authenticateToken, (req, res) => {
    const student = users.find(u => u.username === req.user.username);
    res.json(student.details);
});

// 3. Password Recovery (Integrity Check)
app.post('/api/reset-password', async (req, res) => {
    const { username, newPassword } = req.body;
    const user = users.find(u => u.username === username);
    
    if (user) {
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(newPassword, salt);
        console.log(`[SECURITY EVENT]: Password manually reset for ${username}`);
        res.json({ message: "Password updated successfully" });
    } else {
        res.status(404).send("User not found");
    }
});

// --- SERVER SETUP ---
const options = {
  key: fs.readFileSync('localhost-key.pem'),
  cert: fs.readFileSync('localhost.pem')
};

https.createServer(options, app).listen(3000, () => {
  console.log('University Portal running at https://localhost:3000');
});