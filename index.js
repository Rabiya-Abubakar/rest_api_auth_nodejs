const express = require('express');
const Datastore = require('nedb-promises');
const bcrypt = require('bcryptjs');
const jwt = require('jwt-simple');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const crypto = require('crypto');
const NodeCache = require('node-cache');
const config = require('./config');

// Initialize express
const app = express();
app.use(express.json());

const cache = new NodeCache();
const users = Datastore.create('Users.db');
const userRefreshTokens = Datastore.create('UserRefreshTokens.db');
const userInvalidTokens = Datastore.create('UserInvalidTokens.db');

// Middleware for ensuring authentication
async function ensureAuthenticated(req, res, next) {
    const accessToken = req.headers.authorization?.split(' ')[1];
    if (!accessToken) {
        return res.status(401).json({ message: 'Access token not found' });
    }
    if (await userInvalidTokens.findOne({ accessToken })) {
        return res.status(401).json({ message: 'Access token invalid' });
    }
    try {
        const decodedAccessToken = jwt.decode(accessToken, config.accessTokenSecret);
        req.user = { id: decodedAccessToken.userId };
        req.accessToken = { value: accessToken, exp: decodedAccessToken.exp };
        next();
    } catch (error) {
        return res.status(401).json({ message: 'Access token invalid' });
    }
}

// Middleware for authorization
function authorize(roles = []) {
    return async (req, res, next) => {
        const user = await users.findOne({ _id: req.user.id });
        if (!user || !roles.includes(user.role)) {
            return res.status(403).json({ message: 'Access denied' });
        }
        next();
    };
}

// Endpoints
app.post('/api/auth/register', async (req, res) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) {
        return res.status(422).json({ message: 'Please fill in all fields' });
    }
    if (await users.findOne({ email })) {
        return res.status(409).json({ message: 'Email already exists' });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await users.insert({
        name,
        email,
        password: hashedPassword,
        role: role || 'member',
        '2faEnable': false,
        '2faSecret': null
    });
    res.status(201).json({ message: 'User registered successfully', id: newUser._id });
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(422).json({ message: 'Please fill in all fields' });
    }
    const user = await users.findOne({ email });
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ message: 'Invalid email or password' });
    }
    if (user['2faEnable']) {
        const tempToken = crypto.randomUUID();
        cache.set(config.cacheTemporaryTokenPrefix + tempToken, user._id, config.cacheTemporaryTokenExpiresInSeconds);
        return res.status(200).json({ tempToken, expiresInSeconds: config.cacheTemporaryTokenExpiresInSeconds });
    } else {
        const accessToken = jwt.encode({ userId: user._id }, config.accessTokenSecret, 'HS256');
        const refreshToken = jwt.encode({ userId: user._id }, config.refreshTokenSecret, 'HS256');
        await userRefreshTokens.insert({ refreshToken, userId: user._id });
        res.status(200).json({ id: user._id, name: user.name, email: user.email, accessToken, refreshToken });
    }
});

app.post('/api/auth/login/2fa', async (req, res) => {
    const { tempToken, totp } = req.body;
    if (!tempToken || !totp) {
        return res.status(422).json({ message: 'Please fill in all fields' });
    }
    const userId = cache.get(config.cacheTemporaryTokenPrefix + tempToken);
    if (!userId) {
        return res.status(401).json({ message: 'Temporary token incorrect or expired' });
    }
    const user = await users.findOne({ _id: userId });
    if (!authenticator.check(totp, user['2faSecret'])) {
        return res.status(401).json({ message: 'Invalid TOTP' });
    }
    const accessToken = jwt.encode({ userId: user._id }, config.accessTokenSecret, 'HS256');
    const refreshToken = jwt.encode({ userId: user._id }, config.refreshTokenSecret, 'HS256');
    await userRefreshTokens.insert({ refreshToken, userId: user._id });
    res.status(200).json({ id: user._id, name: user.name, email: user.email, accessToken, refreshToken });
});

app.post('/api/auth/refresh-token', async (req, res) => {
    const { refreshToken } = req.body;
    if (!refreshToken) {
        return res.status(401).json({ message: 'Refresh token not found' });
    }
    try {
        const decodedRefreshToken = jwt.decode(refreshToken, config.refreshTokenSecret);
        const userRefreshToken = await userRefreshTokens.findOne({ refreshToken, userId: decodedRefreshToken.userId });
        if (!userRefreshToken) {
            return res.status(401).json({ message: 'Invalid or expired refresh token' });
        }
        await userRefreshTokens.remove({ _id: userRefreshToken._id });
        const accessToken = jwt.encode({ userId: decodedRefreshToken.userId }, config.accessTokenSecret, 'HS256');
        const newRefreshToken = jwt.encode({ userId: decodedRefreshToken.userId }, config.refreshTokenSecret, 'HS256');
        await userRefreshTokens.insert({ refreshToken: newRefreshToken, userId: decodedRefreshToken.userId });
        res.status(200).json({ accessToken, refreshToken: newRefreshToken });
    } catch {
        res.status(401).json({ message: 'Invalid or expired refresh token' });
    }
});

app.get('/api/auth/2fa/generate', ensureAuthenticated, async (req, res) => {
    const user = await users.findOne({ _id: req.user.id });
    const secret = authenticator.generateSecret();
    const uri = authenticator.keyuri(user.email, 'myapp', secret);
    await users.update({ _id: req.user.id }, { $set: { '2faSecret': secret } });
    const qrCode = await qrcode.toBuffer(uri, { type: 'image/png' });
    res.setHeader('Content-Disposition', 'attachment; filename=qrcode.png');
    res.status(200).type('image/png').send(qrCode);
});

app.post('/api/auth/2fa/validate', ensureAuthenticated, async (req, res) => {
    const { totp } = req.body;
    if (!totp) {
        return res.status(422).json({ message: 'TOTP is required' });
    }
    const user = await users.findOne({ _id: req.user.id });
    if (!authenticator.check(totp, user['2faSecret'])) {
        return res.status(400).json({ message: 'Invalid TOTP' });
    }
    await users.update({ _id: req.user.id }, { $set: { '2faEnable': true } });
    res.status(200).json({ message: '2FA enabled successfully' });
});

app.get('/api/auth/logout', ensureAuthenticated, async (req, res) => {
    await userRefreshTokens.removeMany({ userId: req.user.id });
    await userInvalidTokens.insert({ accessToken: req.accessToken.value, userId: req.user.id, expirationTime: req.accessToken.exp });
    res.status(204).send();
});

app.get('/api/users/current', ensureAuthenticated, async (req, res) => {
    const user = await users.findOne({ _id: req.user.id });
    res.status(200).json({ id: user._id, name: user.name, email: user.email });
});

app.get('/api/admin', ensureAuthenticated, authorize(['admin']), (req, res) => {
    res.status(200).json({ message: 'Only admins can access this route!' });
});

app.get('/api/moderator', ensureAuthenticated, authorize(['admin', 'moderator']), (
