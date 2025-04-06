// models/user.model.js
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true
  },
  passwordHash: {
    type: String,
    required: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  avatar: {
    type: String,
    default: ''
  },
  role: {
    type: String,
    enum: ['admin', 'member'],
    default: 'member'
  },
  settings: {
    theme: {
      type: String,
      default: 'light'
    },
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      push: {
        type: Boolean,
        default: true
      }
    }
  }
}, {
  timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('passwordHash')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.passwordHash = await bcrypt.hash(this.passwordHash, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(password) {
  return bcrypt.compare(password, this.passwordHash);
};

const User = mongoose.model('User', userSchema);

module.exports = User;

// models/workspace.model.js
const mongoose = require('mongoose');

const workspaceSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    default: ''
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  members: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    role: {
      type: String,
      enum: ['admin', 'editor', 'viewer'],
      default: 'viewer'
    }
  }],
  settings: {
    color: {
      type: String,
      default: '#6366f1' // Indigo
    },
    icon: {
      type: String,
      default: 'folder'
    },
    isPrivate: {
      type: Boolean,
      default: false
    }
  }
}, {
  timestamps: true
});

const Workspace = mongoose.model('Workspace', workspaceSchema);

module.exports = Workspace;

// models/project.model.js
const mongoose = require('mongoose');

const projectSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    default: ''
  },
  workspaceId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Workspace',
    required: true
  },
  status: {
    type: String,
    enum: ['planning', 'active', 'on-hold', 'completed', 'archived'],
    default: 'planning'
  },
  startDate: {
    type: Date,
    default: Date.now
  },
  dueDate: Date,
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  members: [{
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    },
    role: {
      type: String,
      enum: ['admin', 'editor', 'viewer'],
      default: 'editor'
    }
  }],
  settings: {
    color: {
      type: String,
      default: '#6366f1' // Indigo
    },
    icon: {
      type: String,
      default: 'clipboard'
    },
    taskViews: {
      board: {
        enabled: {
          type: Boolean,
          default: true
        },
        columns: [{
          name: String,
          color: String
        }]
      },
      list: {
        enabled: {
          type: Boolean,
          default: true
        }
      },
      calendar: {
        enabled: {
          type: Boolean,
          default: true
        }
      },
      gantt: {
        enabled: {
          type: Boolean,
          default: true
        }
      }
    }
  }
}, {
  timestamps: true
});

const Project = mongoose.model('Project', projectSchema);

module.exports = Project;

// models/task.model.js
const mongoose = require('mongoose');

const taskSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
    trim: true
  },
  description: {
    type: String,
    default: ''
  },
  projectId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Project',
    required: true
  },
  status: {
    type: String,
    required: true
  },
  priority: {
    type: String,
    enum: ['low', 'medium', 'high', 'urgent'],
    default: 'medium'
  },
  assignees: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  startDate: Date,
  dueDate: Date,
  completedAt: Date,
  tags: [String],
  attachments: [{
    name: String,
    url: String,
    type: String,
    size: Number,
    uploadedAt: {
      type: Date,
      default: Date.now
    },
    uploadedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User'
    }
  }],
  customFields: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  },
  parent: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Task',
    default: null
  },
  dependencies: [{
    task: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Task'
    },
    type: {
      type: String,
      enum: ['finish-to-start', 'start-to-start', 'finish-to-finish', 'start-to-finish'],
      default: 'finish-to-start'
    }
  }],
  order: {
    type: Number,
    default: 0
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  }
}, {
  timestamps: true
});

// Index for faster queries
taskSchema.index({ projectId: 1, status: 1 });
taskSchema.index({ assignees: 1 });

const Task = mongoose.model('Task', taskSchema);

module.exports = Task;

// models/comment.model.js
const mongoose = require('mongoose');

const commentSchema = new mongoose.Schema({
  content: {
    type: String,
    required: true
  },
  taskId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Task',
    required: true
  },
  author: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  mentions: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }],
  attachments: [{
    name: String,
    url: String,
    type: String,
    size: Number
  }]
}, {
  timestamps: true
});

const Comment = mongoose.model('Comment', commentSchema);

module.exports = Comment;

// models/activity.model.js
const mongoose = require('mongoose');

const activitySchema = new mongoose.Schema({
  entityType: {
    type: String,
    enum: ['task', 'project', 'workspace', 'user'],
    required: true
  },
  entityId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true
  },
  action: {
    type: String,
    required: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  metadata: {
    type: Map,
    of: mongoose.Schema.Types.Mixed
  }
}, {
  timestamps: true
});

// Index for faster queries
activitySchema.index({ entityType: 1, entityId: 1 });
activitySchema.index({ userId: 1 });
activitySchema.index({ createdAt: -1 });

const Activity = mongoose.model('Activity', activitySchema);

module.exports = Activity;

// models/notification.model.js
const mongoose = require('mongoose');

const notificationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  type: {
    type: String,
    enum: ['assignment', 'mention', 'due_date', 'comment', 'status_change', 'project_invite'],
    required: true
  },
  title: {
    type: String,
    required: true
  },
  content: {
    type: String,
    required: true
  },
  relatedTo: {
    type: {
      type: String,
      enum: ['task', 'project', 'workspace', 'comment'],
      required: true
    },
    id: {
      type: mongoose.Schema.Types.ObjectId,
      required: true
    }
  },
  actor: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  read: {
    type: Boolean,
    default: false
  }
}, {
  timestamps: true
});

// Index for faster queries
notificationSchema.index({ userId: 1, read: 1 });
notificationSchema.index({ createdAt: -1 });

const Notification = mongoose.model('Notification', notificationSchema);

module.exports = Notification;

// models/index.js
module.exports = {
  User: require('./user.model'),
  Workspace: require('./workspace.model'),
  Project: require('./project.model'),
  Task: require('./task.model'),
  Comment: require('./comment.model'),
  Activity: require('./activity.model'),
  Notification: require('./notification.model')
};
