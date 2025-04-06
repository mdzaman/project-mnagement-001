// middleware/auth.middleware.js
const jwt = require('jsonwebtoken');
const User = require('../models/user.model');

const authMiddleware = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ message: 'Authorization header missing or invalid' });
    }
    
    const token = authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'Authentication token missing' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-passwordHash');
    
    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }
    
    req.user = user;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: 'Token expired' });
    }
    
    return res.status(401).json({ message: 'Invalid token' });
  }
};

module.exports = authMiddleware;

// controllers/auth.controller.js
const jwt = require('jsonwebtoken');
const User = require('../models/user.model');
const crypto = require('crypto');
const { sendEmail } = require('../utils/email');

// Generate JWT token
const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: '24h'
  });
};

// Register a new user
exports.register = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }
    
    // Create new user
    const user = new User({
      email,
      passwordHash: password,
      name
    });
    
    await user.save();
    
    // Generate token
    const token = generateToken(user._id);
    
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        avatar: user.avatar,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error registering user', error: error.message });
  }
};

// Login user
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    // Generate token
    const token = generateToken(user._id);
    
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        avatar: user.avatar,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error logging in', error: error.message });
  }
};

// Get current user
exports.getCurrentUser = async (req, res) => {
  try {
    res.json({
      user: {
        id: req.user._id,
        email: req.user.email,
        name: req.user.name,
        avatar: req.user.avatar,
        role: req.user.role,
        settings: req.user.settings
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching user', error: error.message });
  }
};

// Forgot password
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User not found with this email' });
    }
    
    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    
    // Hash the token
    const hash = crypto
      .createHash('sha256')
      .update(resetToken)
      .digest('hex');
    
    // Save to user
    user.resetPasswordToken = hash;
    user.resetPasswordExpire = Date.now() + 30 * 60 * 1000; // 30 mins
    await user.save();
    
    // Send email
    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    
    await sendEmail({
      to: user.email,
      subject: 'Password Reset Request',
      text: `You are receiving this email because you (or someone else) has requested a password reset. Please visit: ${resetUrl} to reset your password. This link will expire in 30 minutes.`
    });
    
    res.json({ message: 'Password reset email sent' });
  } catch (error) {
    res.status(500).json({ message: 'Error sending reset email', error: error.message });
  }
};

// Reset password
exports.resetPassword = async (req, res) => {
  try {
    const { token, password } = req.body;
    
    // Hash the token
    const hash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    
    // Find user with token
    const user = await User.findOne({
      resetPasswordToken: hash,
      resetPasswordExpire: { $gt: Date.now() }
    });
    
    if (!user) {
      return res.status(400).json({ message: 'Invalid or expired token' });
    }
    
    // Update password
    user.passwordHash = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpire = undefined;
    await user.save();
    
    res.json({ message: 'Password reset successful' });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password', error: error.message });
  }
};

// routes/auth.routes.js
const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const authMiddleware = require('../middleware/auth.middleware');

// Public routes
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

// Protected routes
router.get('/me', authMiddleware, authController.getCurrentUser);

module.exports = router;

// controllers/workspace.controller.js
const Workspace = require('../models/workspace.model');
const Project = require('../models/project.model');
const Activity = require('../models/activity.model');

// Get all workspaces for current user
exports.getWorkspaces = async (req, res) => {
  try {
    const workspaces = await Workspace.find({
      $or: [
        { owner: req.user._id },
        { 'members.userId': req.user._id }
      ]
    }).sort({ updatedAt: -1 });
    