const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const passport = require('passport');
const BasicStrategy = require('passport-http').BasicStrategy;
const { expressjwt: expressJwt } = require('express-jwt');
const dotenv = require('dotenv');
dotenv.config();

const app = express();
app.use(bodyParser.json());

const SECRET_KEY = process.env.SECRET_KEY || 'secret';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'refresh_secret';
const users = [{ username: 'hello', password: 'world', role: 'admin' }];
let refreshTokens = [];

// Basic Authentication Middleware
passport.use(new BasicStrategy((username, password, done) => {
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) return done(null, false);
    return done(null, user);
}));

// HTTP Basic Route
app.get('/httpbasic', passport.authenticate('basic', { session: false }), (req, res) => {
    res.send(`Hello, ${req.user.username}`);
});

// Middleware for JWT Authentication
const authenticateJWT = expressJwt({ secret: SECRET_KEY, algorithms: ['HS256'] });

// Login route to generate JWT
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) return res.status(401).json({ message: 'Invalid credentials' });
    
    const accessToken = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ username: user.username }, REFRESH_SECRET);
    refreshTokens.push(refreshToken);
    res.json({ accessToken, refreshToken });
});

// Refresh Token Route
app.post('/token', (req, res) => {
    const { token } = req.body;
    if (!token || !refreshTokens.includes(token)) return res.sendStatus(403);
    
    jwt.verify(token, REFRESH_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        const newAccessToken = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '15m' });
        res.json({ accessToken: newAccessToken });
    });
});

// Logout route
app.post('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(t => t !== req.body.token);
    res.sendStatus(204);
});

// Protected Route with JWT
app.get('/posts', authenticateJWT, (req, res) => {
    res.json(['Early bird catches the worm', 'A stitch in time saves nine']);
});

// Role-Based Access Control Middleware
const checkRole = role => (req, res, next) => {
    if (req.auth.role !== role) return res.sendStatus(403);
    next();
};

// Admin-only POST route
app.post('/posts', authenticateJWT, checkRole('admin'), (req, res) => {
    res.json({ message: 'Post added successfully' });
});

const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
