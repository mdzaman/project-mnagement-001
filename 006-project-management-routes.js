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
    
    res.json({ workspaces });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching workspaces', error: error.message });
  }
};

// Create a new workspace
exports.createWorkspace = async (req, res) => {
  try {
    const { name, description, settings } = req.body;
    
    const workspace = new Workspace({
      name,
      description,
      owner: req.user._id,
      members: [{ userId: req.user._id, role: 'admin' }],
      settings
    });
    
    await workspace.save();
    
    // Record activity
    const activity = new Activity({
      entityType: 'workspace',
      entityId: workspace._id,
      action: 'created',
      userId: req.user._id,
      metadata: { workspaceName: workspace.name }
    });
    
    await activity.save();
    
    res.status(201).json({
      message: 'Workspace created successfully',
      workspace
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating workspace', error: error.message });
  }
};

// Get workspace by ID
exports.getWorkspaceById = async (req, res) => {
  try {
    const workspace = await Workspace.findById(req.params.id);
    
    if (!workspace) {
      return res.status(404).json({ message: 'Workspace not found' });
    }
    
    // Check if user has access
    const isMember = 
      workspace.owner.equals(req.user._id) || 
      workspace.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    res.json({ workspace });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching workspace', error: error.message });
  }
};

// Update workspace
exports.updateWorkspace = async (req, res) => {
  try {
    const { name, description, settings } = req.body;
    
    const workspace = await Workspace.findById(req.params.id);
    
    if (!workspace) {
      return res.status(404).json({ message: 'Workspace not found' });
    }
    
    // Check if user is owner or admin
    const isAdmin = 
      workspace.owner.equals(req.user._id) || 
      workspace.members.some(member => 
        member.userId.equals(req.user._id) && member.role === 'admin'
      );
    
    if (!isAdmin) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    // Update fields
    workspace.name = name || workspace.name;
    workspace.description = description || workspace.description;
    
    if (settings) {
      workspace.settings = {
        ...workspace.settings,
        ...settings
      };
    }
    
    await workspace.save();
    
    // Record activity
    const activity = new Activity({
      entityType: 'workspace',
      entityId: workspace._id,
      action: 'updated',
      userId: req.user._id,
      metadata: { workspaceName: workspace.name }
    });
    
    await activity.save();
    
    res.json({
      message: 'Workspace updated successfully',
      workspace
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating workspace', error: error.message });
  }
};

// Delete workspace
exports.deleteWorkspace = async (req, res) => {
  try {
    const workspace = await Workspace.findById(req.params.id);
    
    if (!workspace) {
      return res.status(404).json({ message: 'Workspace not found' });
    }
    
    // Check if user is owner
    if (!workspace.owner.equals(req.user._id)) {
      return res.status(403).json({ message: 'Only the workspace owner can delete it' });
    }
    
    // Delete associated projects
    await Project.deleteMany({ workspaceId: workspace._id });
    
    // Delete workspace
    await workspace.deleteOne();
    
    // Record activity
    const activity = new Activity({
      entityType: 'workspace',
      entityId: workspace._id,
      action: 'deleted',
      userId: req.user._id,
      metadata: { workspaceName: workspace.name }
    });
    
    await activity.save();
    
    res.json({ message: 'Workspace deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting workspace', error: error.message });
  }
};

// Add member to workspace
exports.addMember = async (req, res) => {
  try {
    const { userId, role } = req.body;
    
    if (!userId || !role) {
      return res.status(400).json({ message: 'User ID and role are required' });
    }
    
    const workspace = await Workspace.findById(req.params.id);
    
    if (!workspace) {
      return res.status(404).json({ message: 'Workspace not found' });
    }
    
    // Check if user is admin
    const isAdmin = 
      workspace.owner.equals(req.user._id) || 
      workspace.members.some(member => 
        member.userId.equals(req.user._id) && member.role === 'admin'
      );
    
    if (!isAdmin) {
      return res.status(403).json({ message: 'Only admins can add members' });
    }
    
    // Check if member already exists
    const memberExists = workspace.members.some(member => 
      member.userId.toString() === userId
    );
    
    if (memberExists) {
      return res.status(400).json({ message: 'User is already a member of this workspace' });
    }
    
    // Add member
    workspace.members.push({ userId, role });
    await workspace.save();
    
    // Record activity
    const activity = new Activity({
      entityType: 'workspace',
      entityId: workspace._id,
      action: 'member_added',
      userId: req.user._id,
      metadata: { 
        workspaceName: workspace.name,
        memberId: userId,
        memberRole: role
      }
    });
    
    await activity.save();
    
    res.json({
      message: 'Member added successfully',
      workspace
    });
  } catch (error) {
    res.status(500).json({ message: 'Error adding member', error: error.message });
  }
};

// Remove member from workspace
exports.removeMember = async (req, res) => {
  try {
    const { userId } = req.params;
    
    const workspace = await Workspace.findById(req.params.id);
    
    if (!workspace) {
      return res.status(404).json({ message: 'Workspace not found' });
    }
    
    // Check if user is admin or the member being removed
    const isAdminOrSelf = 
      workspace.owner.equals(req.user._id) || 
      workspace.members.some(member => 
        member.userId.equals(req.user._id) && member.role === 'admin'
      ) ||
      req.user._id.toString() === userId;
    
    if (!isAdminOrSelf) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    // Cannot remove workspace owner
    if (workspace.owner.toString() === userId) {
      return res.status(400).json({ message: 'Cannot remove workspace owner' });
    }
    
    // Remove member
    workspace.members = workspace.members.filter(
      member => member.userId.toString() !== userId
    );
    
    await workspace.save();
    
    // Record activity
    const activity = new Activity({
      entityType: 'workspace',
      entityId: workspace._id,
      action: 'member_removed',
      userId: req.user._id,
      metadata: { 
        workspaceName: workspace.name,
        memberId: userId
      }
    });
    
    await activity.save();
    
    res.json({
      message: 'Member removed successfully',
      workspace
    });
  } catch (error) {
    res.status(500).json({ message: 'Error removing member', error: error.message });
  }
};

// routes/workspace.routes.js
const express = require('express');
const router = express.Router();
const workspaceController = require('../controllers/workspace.controller');
const authMiddleware = require('../middleware/auth.middleware');

// Apply auth middleware to all routes
router.use(authMiddleware);

// Workspace routes
router.get('/', workspaceController.getWorkspaces);
router.post('/', workspaceController.createWorkspace);
router.get('/:id', workspaceController.getWorkspaceById);
router.patch('/:id', workspaceController.updateWorkspace);
router.delete('/:id', workspaceController.deleteWorkspace);
router.post('/:id/members', workspaceController.addMember);
router.delete('/:id/members/:userId', workspaceController.removeMember);

module.exports = router;

// controllers/project.controller.js
const Project = require('../models/project.model');
const Workspace = require('../models/workspace.model');
const Task = require('../models/task.model');
const Activity = require('../models/activity.model');
const Notification = require('../models/notification.model');

// Get all projects for a workspace
exports.getProjects = async (req, res) => {
  try {
    const { workspaceId } = req.params;
    
    // Verify workspace exists
    const workspace = await Workspace.findById(workspaceId);
    
    if (!workspace) {
      return res.status(404).json({ message: 'Workspace not found' });
    }
    
    // Check if user has access to workspace
    const isMember = 
      workspace.owner.equals(req.user._id) || 
      workspace.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this workspace' });
    }
    
    // Get projects
    const projects = await Project.find({ workspaceId })
      .sort({ updatedAt: -1 });
    
    res.json({ projects });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching projects', error: error.message });
  }
};

// Create a new project
exports.createProject = async (req, res) => {
  try {
    const { workspaceId } = req.params;
    const { name, description, startDate, dueDate, settings } = req.body;
    
    // Verify workspace exists
    const workspace = await Workspace.findById(workspaceId);
    
    if (!workspace) {
      return res.status(404).json({ message: 'Workspace not found' });
    }
    
    // Check if user has access to workspace
    const isMember = 
      workspace.owner.equals(req.user._id) || 
      workspace.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this workspace' });
    }
    
    // Create project
    const project = new Project({
      name,
      description,
      workspaceId,
      startDate,
      dueDate,
      owner: req.user._id,
      members: [{ userId: req.user._id, role: 'admin' }],
      settings: settings || {}
    });
    
    // Initialize status columns if not provided
    if (!project.settings.taskViews || !project.settings.taskViews.board || !project.settings.taskViews.board.columns) {
      const defaultColumns = [
        { name: 'To Do', color: '#f3f4f6' },
        { name: 'In Progress', color: '#dbeafe' },
        { name: 'Review', color: '#fef3c7' },
        { name: 'Done', color: '#d1fae5' }
      ];
      
      if (!project.settings.taskViews) {
        project.settings.taskViews = {};
      }
      
      if (!project.settings.taskViews.board) {
        project.settings.taskViews.board = { enabled: true };
      }
      
      project.settings.taskViews.board.columns = defaultColumns;
    }
    
    await project.save();
    
    // Record activity
    const activity = new Activity({
      entityType: 'project',
      entityId: project._id,
      action: 'created',
      userId: req.user._id,
      metadata: { 
        projectName: project.name,
        workspaceId: project.workspaceId
      }
    });
    
    await activity.save();
    
    res.status(201).json({
      message: 'Project created successfully',
      project
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating project', error: error.message });
  }
};

// Get project by ID
exports.getProjectById = async (req, res) => {
  try {
    const { id } = req.params;
    
    const project = await Project.findById(id);
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // Check if user has access
    const isMember = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this project' });
    }
    
    res.json({ project });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching project', error: error.message });
  }
};

// Update project
exports.updateProject = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, description, status, startDate, dueDate, settings } = req.body;
    
    const project = await Project.findById(id);
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // Check if user is admin
    const isAdmin = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => 
        member.userId.equals(req.user._id) && member.role === 'admin'
      );
    
    if (!isAdmin) {
      return res.status(403).json({ message: 'Only project admins can update project details' });
    }
    
    // Update fields
    if (name) project.name = name;
    if (description) project.description = description;
    if (status) project.status = status;
    if (startDate) project.startDate = startDate;
    if (dueDate) project.dueDate = dueDate;
    
    if (settings) {
      project.settings = {
        ...project.settings,
        ...settings
      };
    }
    
    await project.save();
    
    // Record activity
    const activity = new Activity({
      entityType: 'project',
      entityId: project._id,
      action: 'updated',
      userId: req.user._id,
      metadata: { 
        projectName: project.name,
        workspaceId: project.workspaceId
      }
    });
    
    await activity.save();
    
    res.json({
      message: 'Project updated successfully',
      project
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating project', error: error.message });
  }
};

// Delete project
exports.deleteProject = async (req, res) => {
  try {
    const { id } = req.params;
    
    const project = await Project.findById(id);
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // Check if user is owner or admin
    const isOwnerOrAdmin = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => 
        member.userId.equals(req.user._id) && member.role === 'admin'
      );
    
    if (!isOwnerOrAdmin) {
      return res.status(403).json({ message: 'Only project owner or admins can delete the project' });
    }
    
    // Delete associated tasks
    await Task.deleteMany({ projectId: project._id });
    
    // Delete project
    await project.deleteOne();
    
    // Record activity
    const activity = new Activity({
      entityType: 'project',
      entityId: project._id,
      action: 'deleted',
      userId: req.user._id,
      metadata: { 
        projectName: project.name,
        workspaceId: project.workspaceId
      }
    });
    
    await activity.save();
    
    res.json({ message: 'Project deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting project', error: error.message });
  }
};

// Add member to project
exports.addMember = async (req, res) => {
  try {
    const { id } = req.params;
    const { userId, role } = req.body;
    
    if (!userId || !role) {
      return res.status(400).json({ message: 'User ID and role are required' });
    }
    
    const project = await Project.findById(id);
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // Check if user is admin
    const isAdmin = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => 
        member.userId.equals(req.user._id) && member.role === 'admin'
      );
    
    if (!isAdmin) {
      return res.status(403).json({ message: 'Only admins can add members' });
    }
    
    // Check if member already exists
    const memberExists = project.members.some(member => 
      member.userId.toString() === userId
    );
    
    if (memberExists) {
      return res.status(400).json({ message: 'User is already a member of this project' });
    }
    
    // Add member
    project.members.push({ userId, role });
    await project.save();
    
    // Create notification for added user
    const notification = new Notification({
      userId,
      type: 'project_invite',
      title: 'Project Invitation',
      content: `You have been added to project: ${project.name}`,
      relatedTo: {
        type: 'project',
        id: project._id
      },
      actor: req.user._id
    });
    
    await notification.save();
    
    // Record activity
    const activity = new Activity({
      entityType: 'project',
      entityId: project._id,
      action: 'member_added',
      userId: req.user._id,
      metadata: { 
        projectName: project.name,
        memberId: userId,
        memberRole: role
      }
    });
    
    await activity.save();
    
    res.json({
      message: 'Member added successfully',
      project
    });
  } catch (error) {
    res.status(500).json({ message: 'Error adding member', error: error.message });
  }
};

// Remove member from project
exports.removeMember = async (req, res) => {
  try {
    const { id, userId } = req.params;
    
    const project = await Project.findById(id);
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // Check if user is admin or the member being removed
    const isAdminOrSelf = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => 
        member.userId.equals(req.user._id) && member.role === 'admin'
      ) ||
      req.user._id.toString() === userId;
    
    if (!isAdminOrSelf) {
      return res.status(403).json({ message: 'Access denied' });
    }
    
    // Cannot remove project owner
    if (project.owner.toString() === userId) {
      return res.status(400).json({ message: 'Cannot remove project owner' });
    }
    
    // Remove member
    project.members = project.members.filter(
      member => member.userId.toString() !== userId
    );
    
    await project.save();
    
    // Record activity
    const activity = new Activity({
      entityType: 'project',
      entityId: project._id,
      action: 'member_removed',
      userId: req.user._id,
      metadata: { 
        projectName: project.name,
        memberId: userId
      }
    });
    
    await activity.save();
    
    res.json({
      message: 'Member removed successfully',
      project
    });
  } catch (error) {
    res.status(500).json({ message: 'Error removing member', error: error.message });
  }
};

// routes/project.routes.js
const express = require('express');
const router = express.Router();
const projectController = require('../controllers/project.controller');
const authMiddleware = require('../middleware/auth.middleware');

// Apply auth middleware to all routes
router.use(authMiddleware);

// Projects by workspace
router.get('/workspace/:workspaceId', projectController.getProjects);
router.post('/workspace/:workspaceId', projectController.createProject);

// Project operations
router.get('/:id', projectController.getProjectById);
router.patch('/:id', projectController.updateProject);
router.delete('/:id', projectController.deleteProject);
router.post('/:id/members', projectController.addMember);
router.delete('/:id/members/:userId', projectController.removeMember);

module.exports = router;

// controllers/task.controller.js
const Task = require('../models/task.model');
const Project = require('../models/project.model');
const Comment = require('../models/comment.model');
const Activity = require('../models/activity.model');
const Notification = require('../models/notification.model');

// Get all tasks for a project
exports.getTasks = async (req, res) => {
  try {
    const { projectId } = req.params;
    
    // Verify project exists and user has access
    const project = await Project.findById(projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // Check if user has access
    const isMember = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this project' });
    }
    
    // Get tasks
    const tasks = await Task.find({ projectId })
      .populate('assignees', 'name avatar')
      .populate('createdBy', 'name avatar')
      .sort({ order: 1, createdAt: -1 });
    
    res.json({ tasks });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching tasks', error: error.message });
  }
};

// Create a new task
exports.createTask = async (req, res) => {
  try {
    const { projectId } = req.params;
    const { 
      title, 
      description, 
      status, 
      priority, 
      assignees, 
      startDate, 
      dueDate,
      tags,
      customFields,
      parent,
      dependencies
    } = req.body;
    
    // Verify project exists
    const project = await Project.findById(task.projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Associated project not found' });
    }
    
    // Check if user has access to project
    const isMember = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this task' });
    }
    
    res.json({ task });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching task', error: error.message });
  }
};

// Update task
exports.updateTask = async (req, res) => {
  try {
    const { id } = req.params;
    const {
      title,
      description,
      status,
      priority,
      assignees,
      startDate,
      dueDate,
      tags,
      customFields,
      parent,
      dependencies,
      order
    } = req.body;
    
    const task = await Task.findById(id);
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Verify project exists
    const project = await Project.findById(task.projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Associated project not found' });
    }
    
    // Check if user has access to project
    const isMember = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this task' });
    }
    
    // Track if status changed for notifications
    const statusChanged = status && status !== task.status;
    const oldStatus = task.status;
    
    // Track if assignees changed
    let newAssignees = [];
    if (assignees) {
      newAssignees = assignees.filter(
        assignee => !task.assignees.includes(assignee)
      );
    }
    
    // Update fields
    if (title) task.title = title;
    if (description) task.description = description;
    if (status) {
      // Validate status
      const validStatus = project.settings.taskViews.board.columns.some(
        column => column.name === status
      );
      
      if (!validStatus) {
        return res.status(400).json({ message: 'Invalid status for this project' });
      }
      
      task.status = status;
      
      // If status changed to 'Done' or similar, set completedAt
      if (status.toLowerCase().includes('done') || status.toLowerCase().includes('complete')) {
        task.completedAt = new Date();
      } else {
        task.completedAt = undefined;
      }
    }
    if (priority) task.priority = priority;
    if (assignees) task.assignees = assignees;
    if (startDate) task.startDate = startDate;
    if (dueDate) task.dueDate = dueDate;
    if (tags) task.tags = tags;
    if (customFields) {
      task.customFields = {
        ...task.customFields,
        ...customFields
      };
    }
    if (parent !== undefined) task.parent = parent; // Allow null to remove parent
    if (dependencies) task.dependencies = dependencies;
    if (order !== undefined) task.order = order;
    
    await task.save();
    
    // Create notifications for status change
    if (statusChanged) {
      // Notify all assignees except the user who made the change
      const notifications = task.assignees
        .filter(userId => !userId.equals(req.user._id))
        .map(userId => ({
          userId,
          type: 'status_change',
          title: 'Task Status Changed',
          content: `Task "${task.title}" moved from ${oldStatus} to ${task.status}`,
          relatedTo: {
            type: 'task',
            id: task._id
          },
          actor: req.user._id
        }));
        
      if (notifications.length > 0) {
        await Notification.insertMany(notifications);
      }
    }
    
    // Create notifications for new assignees
    if (newAssignees.length > 0) {
      const assigneeNotifications = newAssignees.map(userId => ({
        userId,
        type: 'assignment',
        title: 'New Task Assignment',
        content: `You have been assigned to task: ${task.title}`,
        relatedTo: {
          type: 'task',
          id: task._id
        },
        actor: req.user._id
      }));
      
      await Notification.insertMany(assigneeNotifications);
    }
    
    // Record activity
    const activity = new Activity({
      entityType: 'task',
      entityId: task._id,
      action: 'updated',
      userId: req.user._id,
      metadata: { 
        taskTitle: task.title,
        projectId: task.projectId,
        status: task.status,
        statusChanged: statusChanged,
        oldStatus: statusChanged ? oldStatus : undefined
      }
    });
    
    await activity.save();
    
    // Get populated task
    const populatedTask = await Task.findById(task._id)
      .populate('assignees', 'name avatar')
      .populate('createdBy', 'name avatar');
    
    res.json({
      message: 'Task updated successfully',
      task: populatedTask
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating task', error: error.message });
  }
};

// Update task status
exports.updateTaskStatus = async (req, res) => {
  try {
    const { id } = req.params;
    const { status, order } = req.body;
    
    if (!status) {
      return res.status(400).json({ message: 'Status is required' });
    }
    
    const task = await Task.findById(id);
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Verify project exists
    const project = await Project.findById(task.projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Associated project not found' });
    }
    
    // Check if user has access to project
    const isMember = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this task' });
    }
    
    // Validate status
    const validStatus = project.settings.taskViews.board.columns.some(
      column => column.name === status
    );
    
    if (!validStatus) {
      return res.status(400).json({ message: 'Invalid status for this project' });
    }
    
    // Track old status for notifications
    const oldStatus = task.status;
    const statusChanged = status !== oldStatus;
    
    // Update status
    task.status = status;
    
    // Update order if provided
    if (order !== undefined) {
      task.order = order;
    }
    
    // If status changed to 'Done' or similar, set completedAt
    if (status.toLowerCase().includes('done') || status.toLowerCase().includes('complete')) {
      task.completedAt = new Date();
    } else {
      task.completedAt = undefined;
    }
    
    await task.save();
    
    // Create notifications for status change
    if (statusChanged) {
      // Notify all assignees except the user who made the change
      const notifications = task.assignees
        .filter(userId => !userId.equals(req.user._id))
        .map(userId => ({
          userId,
          type: 'status_change',
          title: 'Task Status Changed',
          content: `Task "${task.title}" moved from ${oldStatus} to ${task.status}`,
          relatedTo: {
            type: 'task',
            id: task._id
          },
          actor: req.user._id
        }));
        
      if (notifications.length > 0) {
        await Notification.insertMany(notifications);
      }
    }
    
    // Record activity
    const activity = new Activity({
      entityType: 'task',
      entityId: task._id,
      action: 'status_changed',
      userId: req.user._id,
      metadata: { 
        taskTitle: task.title,
        projectId: task.projectId,
        oldStatus,
        newStatus: status
      }
    });
    
    await activity.save();
    
    res.json({
      message: 'Task status updated successfully',
      task
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating task status', error: error.message });
  }
};

// Delete task
exports.deleteTask = async (req, res) => {
  try {
    const { id } = req.params;
    
    const task = await Task.findById(id);
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Verify project exists
    const project = await Project.findById(task.projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Associated project not found' });
    }
    
    // Check if user has access to project
    const isProjectAdmin = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => 
        member.userId.equals(req.user._id) && member.role === 'admin'
      );
      
    const isTaskCreator = task.createdBy.equals(req.user._id);
    
    if (!isProjectAdmin && !isTaskCreator) {
      return res.status(403).json({ message: 'Only project admins or task creators can delete tasks' });
    }
    
    // Check for subtasks
    const subtasks = await Task.find({ parent: task._id });
    
    if (subtasks.length > 0) {
      return res.status(400).json({ 
        message: 'This task has subtasks. Please delete or reassign them first.',
        subtasks: subtasks.map(subtask => ({ 
          id: subtask._id,
          title: subtask.title
        }))
      });
    }
    
    // Store task info for activity log
    const taskInfo = {
      title: task.title,
      projectId: task.projectId,
      status: task.status
    };
    
    // Delete comments
    await Comment.deleteMany({ taskId: task._id });
    
    // Delete task
    await task.deleteOne();
    
    // Record activity
    const activity = new Activity({
      entityType: 'task',
      entityId: task._id,
      action: 'deleted',
      userId: req.user._id,
      metadata: taskInfo
    });
    
    await activity.save();
    
    res.json({ message: 'Task deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting task', error: error.message });
  }
};

// Add assignee to task
exports.addAssignee = async (req, res) => {
  try {
    const { id } = req.params;
    const { userId } = req.body;
    
    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }
    
    const task = await Task.findById(id);
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Verify project exists
    const project = await Project.findById(task.projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Associated project not found' });
    }
    
    // Check if user has access to project
    const isMember = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this task' });
    }
    
    // Check if user is project member
    const isProjectMember = 
      project.owner.toString() === userId || 
      project.members.some(member => member.userId.toString() === userId);
    
    if (!isProjectMember) {
      return res.status(400).json({ message: 'User is not a member of the project' });
    }
    
    // Check if already assigned
    if (task.assignees.some(assignee => assignee.toString() === userId)) {
      return res.status(400).json({ message: 'User is already assigned to this task' });
    }
    
    // Add assignee
    task.assignees.push(userId);
    await task.save();
    
    // Create notification
    const notification = new Notification({
      userId,
      type: 'assignment',
      title: 'New Task Assignment',
      content: `You have been assigned to task: ${task.title}`,
      relatedTo: {
        type: 'task',
        id: task._id
      },
      actor: req.user._id
    });
    
    await notification.save();
    
    // Record activity
    const activity = new Activity({
      entityType: 'task',
      entityId: task._id,
      action: 'assignee_added',
      userId: req.user._id,
      metadata: { 
        taskTitle: task.title,
        projectId: task.projectId,
        assigneeId: userId
      }
    });
    
    await activity.save();
    
    // Get populated task
    const populatedTask = await Task.findById(task._id)
      .populate('assignees', 'name avatar')
      .populate('createdBy', 'name avatar');
    
    res.json({
      message: 'Assignee added successfully',
      task: populatedTask
    });
  } catch (error) {
    res.status(500).json({ message: 'Error adding assignee', error: error.message });
  }
};

// Remove assignee from task
exports.removeAssignee = async (req, res) => {
  try {
    const { id, userId } = req.params;
    
    const task = await Task.findById(id);
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Verify project exists
    const project = await Project.findById(task.projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Associated project not found' });
    }
    
    // Check if user has access to project or is the assignee being removed
    const isMember = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => member.userId.equals(req.user._id));
    
    const isSelf = req.user._id.toString() === userId;
    
    if (!isMember && !isSelf) {
      return res.status(403).json({ message: 'Access denied to this task' });
    }
    
    // Check if user is assigned
    if (!task.assignees.some(assignee => assignee.toString() === userId)) {
      return res.status(400).json({ message: 'User is not assigned to this task' });
    }
    
    // Remove assignee
    task.assignees = task.assignees.filter(
      assignee => assignee.toString() !== userId
    );
    
    await task.save();
    
    // Record activity
    const activity = new Activity({
      entityType: 'task',
      entityId: task._id,
      action: 'assignee_removed',
      userId: req.user._id,
      metadata: { 
        taskTitle: task.title,
        projectId: task.projectId,
        assigneeId: userId
      }
    });
    
    await activity.save();
    
    // Get populated task
    const populatedTask = await Task.findById(task._id)
      .populate('assignees', 'name avatar')
      .populate('createdBy', 'name avatar');
    
    res.json({
      message: 'Assignee removed successfully',
      task: populatedTask
    });
  } catch (error) {
    res.status(500).json({ message: 'Error removing assignee', error: error.message });
  }
};

// Get task comments
exports.getComments = async (req, res) => {
  try {
    const { id } = req.params;
    
    const task = await Task.findById(id);
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Verify project exists
    const project = await Project.findById(task.projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Associated project not found' });
    }
    
    // Check if user has access to project
    const isMember = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this task' });
    }
    
    // Get comments
    const comments = await Comment.find({ taskId: id })
      .populate('author', 'name avatar')
      .populate('mentions', 'name avatar')
      .sort({ createdAt: 1 });
    
    res.json({ comments });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching comments', error: error.message });
  }
};

// routes/task.routes.js
const express = require('express');
const router = express.Router();
const taskController = require('../controllers/task.controller');
const commentController = require('../controllers/comment.controller');
const authMiddleware = require('../middleware/auth.middleware');

// Apply auth middleware to all routes
router.use(authMiddleware);

// Tasks by project
router.get('/project/:projectId', taskController.getTasks);
router.post('/project/:projectId', taskController.createTask);

// Task operations
router.get('/:id', taskController.getTaskById);
router.patch('/:id', taskController.updateTask);
router.delete('/:id', taskController.deleteTask);
router.patch('/:id/status', taskController.updateTaskStatus);
router.post('/:id/assignees', taskController.addAssignee);
router.delete('/:id/assignees/:userId', taskController.removeAssignee);
router.get('/:id/comments', taskController.getComments);

// Comment routes are handled by comment controller
router.post('/:id/comments', commentController.createComment);

module.exports = router;

// controllers/comment.controller.js
const Comment = require('../models/comment.model');
const Task = require('../models/task.model');
const Project = require('../models/project.model');
const Activity = require('../models/activity.model');
const Notification = require('../models/notification.model');

// Create a new comment
exports.createComment = async (req, res) => {
  try {
    const { id: taskId } = req.params;
    const { content, mentions, attachments } = req.body;
    
    if (!content || content.trim() === '') {
      return res.status(400).json({ message: 'Comment content is required' });
    }
    
    // Verify task exists
    const task = await Task.findById(taskId);
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Verify project exists
    const project = await Project.findById(task.projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Associated project not found' });
    }
    
    // Check if user has access to project
    const isMember = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this task' });
    }
    
    // Create comment
    const comment = new Comment({
      content,
      taskId,
      author: req.user._id,
      mentions: mentions || [],
      attachments: attachments || []
    });
    
    await comment.save();
    
    // Create notifications for mentions
    if (mentions && mentions.length > 0) {
      const mentionNotifications = mentions
        .filter(userId => userId !== req.user._id.toString())
        .map(userId => ({
          userId,
          type: 'mention',
          title: 'You were mentioned in a comment',
          content: `${req.user.name} mentioned you in task: ${task.title}`,
          relatedTo: {
            type: 'comment',
            id: comment._id
          },
          actor: req.user._id
        }));
      
      if (mentionNotifications.length > 0) {
        await Notification.insertMany(mentionNotifications);
      }
    }
    
    // Notify task assignees about the new comment
    const assigneeNotifications = task.assignees
      .filter(userId => !userId.equals(req.user._id))
      .filter(userId => !mentions || !mentions.includes(userId.toString()))
      .map(userId => ({
        userId,
        type: 'comment',
        title: 'New comment on assigned task',
        content: `${req.user.name} commented on task: ${task.title}`,
        relatedTo: {
          type: 'comment',
          id: comment._id
        },
        actor: req.user._id
      }));
    
    if (assigneeNotifications.length > 0) {
      await Notification.insertMany(assigneeNotifications);
    }
    
    // Record activity
    const activity = new Activity({
      entityType: 'task',
      entityId: task._id,
      action: 'comment_added',
      userId: req.user._id,
      metadata: { 
        taskTitle: task.title,
        projectId: task.projectId,
        commentId: comment._id
      }
    });
    
    await activity.save();
    
    // Get populated comment
    const populatedComment = await Comment.findById(comment._id)
      .populate('author', 'name avatar')
      .populate('mentions', 'name avatar');
    
    res.status(201).json({
      message: 'Comment created successfully',
      comment: populatedComment
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating comment', error: error.message });
  }
};

// Update comment
exports.updateComment = async (req, res) => {
  try {
    const { id } = req.params;
    const { content, mentions, attachments } = req.body;
    
    if (!content || content.trim() === '') {
      return res.status(400).json({ message: 'Comment content is required' });
    }
    
    const comment = await Comment.findById(id);
    
    if (!comment) {
      return res.status(404).json({ message: 'Comment not found' });
    }
    
    // Check if user is the author
    if (!comment.author.equals(req.user._id)) {
      return res.status(403).json({ message: 'Only the comment author can update it' });
    }
    
    // Update fields
    comment.content = content;
    
    if (mentions) {
      // Find new mentions
      const newMentions = mentions.filter(
        userId => !comment.mentions.includes(userId)
      );
      
      comment.mentions = mentions;
      
      // Create notifications for new mentions
      if (newMentions.length > 0) {
        const mentionNotifications = newMentions
          .filter(userId => userId !== req.user._id.toString())
          .map(userId => ({
            userId,
            type: 'mention',
            title: 'You were mentioned in a comment',
            content: `${req.user.name} mentioned you in a comment`,
            relatedTo: {
              type: 'comment',
              id: comment._id
            },
            actor: req.user._id
          }));
        
        if (mentionNotifications.length > 0) {
          await Notification.insertMany(mentionNotifications);
        }
      }
    }
    
    if (attachments) {
      comment.attachments = attachments;
    }
    
    await comment.save();
    
    // Get populated comment
    const populatedComment = await Comment.findById(comment._id)
      .populate('author', 'name avatar')
      .populate('mentions', 'name avatar');
    
    res.json({
      message: 'Comment updated successfully',
      comment: populatedComment
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating comment', error: error.message });
  }
};

// Delete comment
exports.deleteComment = async (req, res) => {
  try {
    const { id } = req.params;
    
    const comment = await Comment.findById(id);
    
    if (!comment) {
      return res.status(404).json({ message: 'Comment not found' });
    }
    
    // Get task and project for permission check
    const task = await Task.findById(comment.taskId);
    
    if (!task) {
      return res.status(404).json({ message: 'Associated task not found' });
    }
    
    const project = await Project.findById(task.projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Associated project not found' });
    }
    
    // Check if user is the author or a project admin
    const isAuthor = comment.author.equals(req.user._id);
    const isProjectAdmin = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => 
        member.userId.equals(req.user._id) && member.role === 'admin'
      );
    
    if (!isAuthor && !isProjectAdmin) {
      return res.status(403).json({ message: 'Only the author or project admins can delete this comment' });
    }
    
    // Delete comment
    await comment.deleteOne();
    
    // Record activity
    const activity = new Activity({
      entityType: 'task',
      entityId: task._id,
      action: 'comment_deleted',
      userId: req.user._id,
      metadata: { 
        taskTitle: task.title,
        projectId: task.projectId,
        commentId: comment._id
      }
    });
    
    await activity.save();
    
    res.json({ message: 'Comment deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting comment', error: error.message });
  }
};

// routes/comment.routes.js
const express = require('express');
const router = express.Router();
const commentController = require('../controllers/comment.controller');
const authMiddleware = require('../middleware/auth.middleware');

// Apply auth middleware to all routes
router.use(authMiddleware);

// Comment routes
router.patch('/:id', commentController.updateComment);
router.delete('/:id', commentController.deleteComment);

module.exports = router; = await Project.findById(projectId);
    
    if (!project) {
      return res.status(404).json({ message: 'Project not found' });
    }
    
    // Check if user has access
    const isMember = 
      project.owner.equals(req.user._id) || 
      project.members.some(member => member.userId.equals(req.user._id));
    
    if (!isMember) {
      return res.status(403).json({ message: 'Access denied to this project' });
    }
    
    // Validate status
    const validStatus = project.settings.taskViews.board.columns.some(
      column => column.name === status
    );
    
    if (!validStatus) {
      return res.status(400).json({ message: 'Invalid status for this project' });
    }
    
    // Get highest order for current status to position the new task at the end
    let maxOrder = 0;
    const lastTask = await Task.findOne({ projectId, status })
      .sort({ order: -1 })
      .limit(1);
      
    if (lastTask) {
      maxOrder = lastTask.order + 1;
    }
    
    // Create task
    const task = new Task({
      title,
      description,
      projectId,
      status,
      priority: priority || 'medium',
      assignees: assignees || [],
      startDate,
      dueDate,
      tags: tags || [],
      customFields: customFields || {},
      parent,
      dependencies: dependencies || [],
      order: maxOrder,
      createdBy: req.user._id
    });
    
    await task.save();
    
    // Create notifications for assignees
    if (assignees && assignees.length > 0) {
      const notifications = assignees.map(userId => ({
        userId,
        type: 'assignment',
        title: 'New Task Assignment',
        content: `You have been assigned to task: ${task.title}`,
        relatedTo: {
          type: 'task',
          id: task._id
        },
        actor: req.user._id
      }));
      
      await Notification.insertMany(notifications);
    }
    
    // Record activity
    const activity = new Activity({
      entityType: 'task',
      entityId: task._id,
      action: 'created',
      userId: req.user._id,
      metadata: { 
        taskTitle: task.title,
        projectId: task.projectId,
        status: task.status
      }
    });
    
    await activity.save();
    
    // Get populated task
    const populatedTask = await Task.findById(task._id)
      .populate('assignees', 'name avatar')
      .populate('createdBy', 'name avatar');
    
    res.status(201).json({
      message: 'Task created successfully',
      task: populatedTask
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating task', error: error.message });
  }
};

// Get task by ID
exports.getTaskById = async (req, res) => {
  try {
    const { id } = req.params;
    
    const task = await Task.findById(id)
      .populate('assignees', 'name avatar')
      .populate('createdBy', 'name avatar')
      .populate({
        path: 'parent',
        select: 'title status'
      })
      .populate({
        path: 'dependencies.task',
        select: 'title status'
      });
    
    if (!task) {
      return res.status(404).json({ message: 'Task not found' });
    }
    
    // Verify project exists
    const project
