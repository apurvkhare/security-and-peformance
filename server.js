// server.js
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path'); // Import path module
const app = express();
const PORT = 3000;

// Middleware
app.use(express.json()); // Parse JSON bodies
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded bodies
app.use(express.static('public')); // Serve static files

// Create an in-memory SQLite database
const db = new sqlite3.Database(':memory:');

// Initialize the database with some user data
db.serialize(() => {
    db.run("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, email TEXT, password TEXT, dob TEXT, address TEXT)");
    const stmt = db.prepare("INSERT INTO users (name, email, password, dob, address) VALUES (?, ?, ?, ?, ?)");
    stmt.run("Alice", "alice@example.com", "password123", "1990-01-01", "123 Main St, City A");
    stmt.run("Bob", "bob@example.com", "password456", "1992-02-02", "456 Elm St, City B");
    stmt.run("Charlie", "charlie@example.com", "password789", "1994-03-03", "789 Oak St, City C");
    stmt.finalize();
});

// Serve index.html at the root URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html')); // Send the index.html file
});

// SQL Injection Example
app.get('/users', (req, res) => {
    const { id } = req.query;
    // Vulnerable to SQL Injection
    const query = `SELECT * FROM users WHERE id = ${id}`; // Unsafe query
    db.all(query, [], (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
            return;
        }
        res.json(rows.length > 0 ? rows : { error: 'User not found' });
    });
});

// XSS Example
app.post('/submit', (req, res) => {
    const { comment } = req.body;
    // Vulnerable to XSS
    res.send(`<h1>Your Comment</h1><p>${comment}</p>`); // Unsafe output
});

// CSRF Example
app.post('/csrf', (req, res) => {
    const { action } = req.body;
    if (action === 'delete') {
        // Simulate a delete action
        res.send('Item deleted!');
    } else {
        res.send('No action taken.');
    }
});

// Start server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});

