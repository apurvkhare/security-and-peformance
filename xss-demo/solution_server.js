// secure-server.js
const express = require('express');
const sqlite3 = require('sqlite3');
const DOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const window = new JSDOM('').window;
const purify = DOMPurify(window);
const helmet = require('helmet');
const escape = require('escape-html');
const app = express();

// Security middleware
app.use(helmet()); // Adds various HTTP headers for security
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

const db = new sqlite3.Database(':memory:');

// Database setup (same as vulnerable version)
// ... (previous database setup code)

// Secure Routes

// 1. Profile update - Protected from Stored XSS
app.post('/api/profile', (req, res) => {
  const { username, bio } = req.body;
  
  // Sanitize the bio input
  const sanitizedBio = purify.sanitize(bio, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong'], // Allow basic formatting
    ALLOWED_ATTR: [] // No attributes allowed
  });
  
  db.run('UPDATE users SET profile_bio = ? WHERE username = ?', 
    [sanitizedBio, username], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// 2. Comment submission - Protected from Stored XSS
app.post('/api/posts/:postId/comments', (req, res) => {
  const { userId, content } = req.body;
  const postId = req.params.postId;
  
  // Sanitize the comment content
  const sanitizedContent = purify.sanitize(content, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong'],
    ALLOWED_ATTR: []
  });
  
  db.run('INSERT INTO comments (post_id, user_id, content) VALUES (?, ?, ?)',
    [postId, userId, sanitizedContent], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// 3. Search - Protected from Reflected XSS
app.get('/api/search', (req, res) => {
  const searchTerm = req.query.q;
  
  db.all(`
    SELECT blog_posts.*, users.username 
    FROM blog_posts 
    JOIN users ON blog_posts.user_id = users.id 
    WHERE title LIKE ?`, 
    [`%${searchTerm}%`], 
    (err, posts) => {
      if (err) return res.status(500).json({ error: err.message });
      
      // Escape all user-provided data before inserting into HTML
      const safeHtml = `
        <h2>Search Results for: ${escape(searchTerm)}</h2>
        <div>${posts.map(post => `
          <div>
            <h3>${escape(post.title)}</h3>
            <p>By: ${escape(post.username)}</p>
          </div>
        `).join('')}</div>
      `;
      
      res.send(safeHtml);
    });
});

// 4. Get post with comments - Protected from XSS
app.get('/api/posts/:id', (req, res) => {
  const postId = req.params.id;
  
  db.get('SELECT * FROM blog_posts WHERE id = ?', [postId], (err, post) => {
    if (err) return res.status(500).json({ error: err.message });
    
    db.all(`
      SELECT comments.*, users.username 
      FROM comments 
      JOIN users ON comments.user_id = users.id 
      WHERE post_id = ?`, 
      [postId], 
      (err, comments) => {
        if (err) return res.status(500).json({ error: err.message });
        
        // Sanitize post and comment content before sending
        const sanitizedPost = {
          ...post,
          title: escape(post.title),
          content: purify.sanitize(post.content)
        };
        
        const sanitizedComments = comments.map(comment => ({
          ...comment,
          username: escape(comment.username),
          content: purify.sanitize(comment.content)
        }));
        
        res.json({
          post: sanitizedPost,
          comments: sanitizedComments
        });
      });
  });
});

app.get('/api/theme-preview', (req, res) => {
    const allowedThemes = ['light', 'dark'];
    const { theme, fontSize } = req.query;
    
    // Validate and sanitize inputs
    const sanitizedTheme = allowedThemes.includes(theme) ? theme : 'light';
    const sanitizedFontSize = /^\d+px$/.test(fontSize) ? fontSize : '16px';
    
    res.json({ 
      theme: sanitizedTheme, 
      fontSize: sanitizedFontSize 
    });
});
  

app.listen(3001, () => {
  console.log('Secure server running on port 3001');
});