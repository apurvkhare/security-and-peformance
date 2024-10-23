// server.js
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const path = require('path');
const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
    name: 'bankSessionId',
    secret: 'your-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
    cookie: { 
        secure: false,  // Set to true in production with HTTPS
        httpOnly: true,
        sameSite: 'lax'  // Allow cookies to be sent in same-site requests
    } // Set to true in production with HTTPS
}));

app.use(express.static(path.join(__dirname)));
// Simulated database
let userBalances = {
    'user123': 1000
};

// Login simulation (simplified for demo)
app.post('/login', (req, res) => {
    const userId = 'user123'; // Simulated user
    req.session.userId = userId;
    
    // Generate CSRF token for secure version
    req.session.csrfToken = crypto.randomBytes(32).toString('hex');
    
    res.json({ 
        message: 'Logged in successfully',
        balance: userBalances[userId],
        csrfToken: req.session.csrfToken 
    });
});

// Vulnerable endpoint - No CSRF protection
app.post('/api/vulnerable/transfer', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Please login first' });
    }

    const amount = parseInt(req.body.amount);
    const toAccount = req.body.toAccount;

    if (userBalances[req.session.userId] >= amount) {
        userBalances[req.session.userId] -= amount;
        return res.json({
            message: `Transferred $${amount} to ${toAccount}`,
            newBalance: userBalances[req.session.userId]
        });
    }
    
    res.status(400).json({ error: 'Insufficient funds' });
});

// Secure endpoint - With CSRF protection
app.post('/api/secure/transfer', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Please login first' });
    }

    // CSRF Token validation
    const token = req.body._csrf || req.headers['x-csrf-token'];
    if (!token || token !== req.session.csrfToken) {
        return res.status(403).json({ error: 'Invalid CSRF token' });
    }

    const amount = parseInt(req.body.amount);
    const toAccount = req.body.toAccount;

    if (userBalances[req.session.userId] >= amount) {
        userBalances[req.session.userId] -= amount;
        return res.json({
            message: `Transferred $${amount} to ${toAccount}`,
            newBalance: userBalances[req.session.userId]
        });
    }
    
    res.status(400).json({ error: 'Insufficient funds' });
});

// Get current balance
app.get('/api/balance', (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Please login first' });
    }
    res.json({ balance: userBalances[req.session.userId] });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});