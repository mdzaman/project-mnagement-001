import React, { useState } from 'react';
import { ChevronDown, Grid, Calendar, List, BarChart2, Clock, Star, Settings, Bell, Search, Plus, Users, Folder, Home, Menu, X, Filter, MoreHorizontal } from 'lucide-react';

const ProjectManagementUI = () => {
  // State management
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [selectedWorkspace, setSelectedWorkspace] = useState('Marketing Team');
  const [selectedView, setSelectedView] = useState('board');
  const [selectedProject, setSelectedProject] = useState('Website Redesign');
  
  // Sample data
  const workspaces = ['Marketing Team', 'Product Development', 'Personal'];
  const projects = [
    { id: 1, name: 'Website Redesign', progress: 65, dueDate: '2025-04-20', priority: 'High' },
    { id: 2, name: 'Q2 Campaign', progress: 30, dueDate: '2025-05-15', priority: 'Medium' },
    { id: 3, name: 'Brand Guidelines', progress: 80, dueDate: '2025-04-10', priority: 'Low' }
  ];
  
  const tasks = [
    { id: 1, title: 'Design Homepage Mock', status: 'In Progress', assignee: 'Alex Kim', dueDate: '2025-04-08' },
    { id: 2, title: 'Create Content Strategy', status: 'To Do', assignee: 'Jamie Chen', dueDate: '2025-04-12' },
    { id: 3, title: 'Review Design System', status: 'In Progress', assignee: 'Morgan Smith', dueDate: '2025-04-09' },
    { id: 4, title: 'Integrate Analytics', status: 'To Do', assignee: 'Riley Johnson', dueDate: '2025-04-15' },
    { id: 5, title: 'User Testing', status: 'To Do', assignee: 'Casey Wilson', dueDate: '2025-04-18' },
    { id: 6, title: 'SEO Optimization', status: 'Done', assignee: 'Taylor Brown', dueDate: '2025-04-05' }
  ];

  const statuses = ['To Do', 'In Progress', 'Review', 'Done'];

  // Group tasks by status for Kanban view
  const tasksByStatus = statuses.reduce((acc, status) => {
    acc[status] = tasks.filter(task => task.status === status);
    return acc;
  }, {});

  // Calculate days remaining
  const calculateDaysRemaining = (dueDate) => {
    const today = new Date();
    const due = new Date(dueDate);
    const diffTime = due - today;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    return diffDays;
  };

  // Toggle sidebar
  const toggleSidebar = () => {
    setSidebarCollapsed(!sidebarCollapsed);
  };

  // Render badge based on priority
  const renderPriorityBadge = (priority) => {
    const colors = {
      'High': 'bg-red-100 text-red-800',
      'Medium': 'bg-yellow-100 text-yellow-800',
      'Low': 'bg-green-100 text-green-800'
    };
    
    return (
      <span className={`text-xs px-2 py-1 rounded-full ${colors[priority]}`}>
        {priority}
      </span>
    );
  };

  return (
    <div className="flex h-screen bg-gray-50 text-gray-800">
      {/* Sidebar */}
      <div className={`bg-white border-r border-gray-200 transition-all duration-300 ${sidebarCollapsed ? 'w-16' : 'w-64'}`}>
        <div className="p-4 flex items-center justify-between border-b border-gray-200">
          {!sidebarCollapsed && <h1 className="font-bold text-xl text-indigo-600">Planify</h1>}
          <button onClick={toggleSidebar} className="p-1 rounded-lg hover:bg-gray-100">
            {sidebarCollapsed ? <Menu size={20} /> : <X size={20} />}
          </button>
        </div>
        
        {/* User profile */}
        <div className="p-4 flex items-center border-b border-gray-200">
          <div className="w-8 h-8 rounded-full bg-indigo-500 flex items-center justify-center text-white font-medium">
            JS
          </div>
          {!sidebarCollapsed && (
            <div className="ml-3">
              <p className="text-sm font-medium">Jordan Smith</p>
              <p className="text-xs text-gray-500">Product Manager</p>
            </div>
          )}
        </div>

        {/* Navigation */}
        <nav className="px-2 py-4">
          <div className={`mb-4 ${!sidebarCollapsed && 'px-2'}`}>
            {!sidebarCollapsed && <p className="text-xs uppercase text-gray-500 font-semibold mb-2">Main</p>}
            <ul className="space-y-1">
              <li>
                <a href="#" className="flex items-center p-2 rounded-lg text-gray-800 hover:bg-indigo-50 hover:text-indigo-700">
                  <Home size={18} />
                  {!sidebarCollapsed && <span className="ml-3">Dashboard</span>}
                </a>
              </li>
              <li>
                <a href="#" className="flex items-center p-2 rounded-lg bg-indigo-50 text-indigo-700">
                  <Folder size={18} />
                  {!sidebarCollapsed && <span className="ml-3">Projects</span>}
                </a>
              </li>
              <li>
                <a href="#" className="flex items-center p-2 rounded-lg text-gray-800 hover:bg-indigo-50 hover:text-indigo-700">
                  <Users size={18} />
                  {!sidebarCollapsed && <span className="ml-3">Team</span>}
                </a>
              </li>
              <li>
                <a href="#" className="flex items-center p-2 rounded-lg text-gray-800 hover:bg-indigo-50 hover:text-indigo-700">
                  <Clock size={18} />
                  {!sidebarCollapsed && <span className="ml-3">Time Tracking</span>}
                </a>
              </li>
              <li>
                <a href="#" className="flex items-center p-2 rounded-lg text-gray-800 hover:bg-indigo-50 hover:text-indigo-700">
                  <BarChart2 size={18} />
                  {!sidebarCollapsed && <span className="ml-3">Reports</span>}
                </a>
              </li>
            </ul>
          </div>
          
          {!sidebarCollapsed && (
            <div className="px-2 mb-4">
              <p className="text-xs uppercase text-gray-500 font-semibold mb-2">Workspaces</p>
              <ul className="space-y-1">
                {workspaces.map(workspace => (
                  <li key={workspace}>
                    <button 
                      onClick={() => setSelectedWorkspace(workspace)}
                      className={`w-full text-left flex items-center p-2 rounded-lg ${selectedWorkspace === workspace ? 'bg-indigo-50 text-indigo-700' : 'text-gray-800 hover:bg-indigo-50 hover:text-indigo-700'}`}
                    >
                      <div className={`w-2 h-2 rounded-full ${workspace === 'Marketing Team' ? 'bg-purple-500' : workspace === 'Product Development' ? 'bg-blue-500' : 'bg-green-500'}`}></div>
                      <span className="ml-3 truncate">{workspace}</span>
                    </button>
                  </li>
                ))}
                <li>
                  <button className="w-full text-left flex items-center p-2 rounded-lg text-indigo-600 hover:bg-indigo-50">
                    <Plus size={16} />
                    <span className="ml-3">Add Workspace</span>
                  </button>
                </li>
              </ul>
            </div>
          )}
        </nav>
      </div>

      {/* Main content */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Top navigation */}
        <header className="bg-white border-b border-gray-200">
          <div className="flex items-center justify-between px-6 py-3">
            <div className="flex items-center">
              <h2 className="text-xl font-semibold">{selectedProject}</h2>
              <div className="ml-4 flex">
                <button className="p-1 rounded-md hover:bg-gray-100 text-gray-500" title="Star Project">
                  <Star size={18} />
                </button>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <div className="relative">
                <input
                  type="text"
                  placeholder="Search..."
                  className="py-2 pl-10 pr-4 w-64 rounded-lg border border-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                />
                <Search className="absolute left-3 top-2.5 text-gray-400" size={18} />
              </div>
              
              <button className="p-2 rounded-lg hover:bg-gray-100 relative">
                <Bell size={20} />
                <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500"></span>
              </button>
              
              <button className="p-2 rounded-lg hover:bg-gray-100">
                <Settings size={20} />
              </button>
              
              <div className="flex -space-x-2">
                <div className="w-8 h-8 rounded-full border-2 border-white bg-indigo-500 flex items-center justify-center text-white text-xs font-medium">AK</div>
                <div className="w-8 h-8 rounded-full border-2 border-white bg-pink-500 flex items-center justify-center text-white text-xs font-medium">JC</div>
                <div className="w-8 h-8 rounded-full border-2 border-white bg-green-500 flex items-center justify-center text-white text-xs font-medium">MS</div>
                <div className="w-8 h-8 rounded-full border-2 border-white bg-gray-200 flex items-center justify-center text-gray-600 text-xs">+3</div>
              </div>
            </div>
          </div>
          
          {/* View selector */}
          <div className="px-6 py-2 flex items-center border-t border-gray-200">
            <div className="flex space-x-1">
              <button 
                onClick={() => setSelectedView('board')} 
                className={`px-3 py-1 rounded-md flex items-center ${selectedView === 'board' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-700 hover:bg-gray-100'}`}
              >
                <Grid size={16} className="mr-2" />
                Board
              </button>
              <button 
                onClick={() => setSelectedView('list')} 
                className={`px-3 py-1 rounded-md flex items-center ${selectedView === 'list' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-700 hover:bg-gray-100'}`}
              >
                <List size={16} className="mr-2" />
                List
              </button>
              <button 
                onClick={() => setSelectedView('calendar')} 
                className={`px-3 py-1 rounded-md flex items-center ${selectedView === 'calendar' ? 'bg-indigo-50 text-indigo-700' : 'text-gray-700 hover:bg-gray-100'}`}
              >
                <Calendar size={16} className="mr-2" />
                Calendar
              </button>
            </div>
            
            <div className="ml-auto flex items-center space-x-2">
              <button className="px-3 py-1 rounded-md text-gray-700 hover:bg-gray-100 flex items-center">
                <Filter size={16} className="mr-2" />
                Filter
              </button>
              <button className="px-3 py-1 rounded-md bg-indigo-600 text-white hover:bg-indigo-700 flex items-center">
                <Plus size={16} className="mr-2" />
                Add Task
              </button>
            </div>
          </div>
        </header>

        {/* Project content */}
        <main className="flex-1 overflow-auto p-6">
          {/* Kanban board view */}
          {selectedView === 'board' && (
            <div className="flex h-full space-x-4">
              {statuses.map(status => (
                <div key={status} className="w-80 flex-shrink-0">
                  <div className="bg-gray-100 rounded-t-lg px-3 py-2 flex items-center justify-between">
                    <h3 className="font-medium">{status}</h3>
                    <span className="bg-gray-200 text-gray-800 text-xs font-medium px-2 py-0.5 rounded-full">
                      {(tasksByStatus[status] || []).length}
                    </span>
                  </div>
                  
                  <div className="mt-2 space-y-3">
                    {(tasksByStatus[status] || []).map(task => (
                      <div key={task.id} className="bg-white p-3 rounded-lg shadow-sm border border-gray-200 hover:shadow-md transition-shadow cursor-pointer">
                        <h4 className="font-medium mb-2">{task.title}</h4>
                        <div className="flex items-center justify-between text-sm text-gray-500 mb-3">
                          <div className="flex items-center">
                            <Clock size={14} className="mr-1" />
                            <span className={`${calculateDaysRemaining(task.dueDate) < 2 ? 'text-red-600 font-medium' : ''}`}>
                              {calculateDaysRemaining(task.dueDate)} days left
                            </span>
                          </div>
                        </div>
                        <div className="flex items-center justify-between">
                          <div className="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center text-white text-xs font-medium">
                            {task.assignee.split(' ').map(n => n[0]).join('')}
                          </div>
                          <button className="text-gray-400 hover:text-gray-600">
                            <MoreHorizontal size={16} />
                          </button>
                        </div>
                      </div>
                    ))}
                    <button className="w-full py-2 border-2 border-dashed border-gray-300 rounded-lg text-gray-500 hover:bg-gray-50 flex items-center justify-center">
                      <Plus size={16} className="mr-1" />
                      Add Task
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
          
          {/* List view */}
          {selectedView === 'list' && (
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Task</th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Assignee</th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Due Date</th>
                    <th scope="col" className="relative px-6 py-3">
                      <span className="sr-only">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-white divide-y divide-gray-200">
                  {tasks.map(task => (
                    <tr key={task.id} className="hover:bg-gray-50">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="text-sm font-medium text-gray-900">{task.title}</div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <span className={`px-2 inline-flex text-xs leading-5 font-semibold rounded-full ${
                          task.status === 'To Do' ? 'bg-yellow-100 text-yellow-800' : 
                          task.status === 'In Progress' ? 'bg-blue-100 text-blue-800' : 
                          task.status === 'Review' ? 'bg-purple-100 text-purple-800' : 
                          'bg-green-100 text-green-800'
                        }`}>
                          {task.status}
                        </span>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <div className="flex-shrink-0 h-8 w-8 rounded-full bg-blue-500 flex items-center justify-center text-white text-xs font-medium">
                            {task.assignee.split(' ').map(n => n[0]).join('')}
                          </div>
                          <div className="ml-4">
                            <div className="text-sm font-medium text-gray-900">{task.assignee}</div>
                          </div>
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className={`text-sm ${calculateDaysRemaining(task.dueDate) < 2 ? 'text-red-600 font-medium' : 'text-gray-500'}`}>
                          {task.dueDate} ({calculateDaysRemaining(task.dueDate)} days)
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <button className="text-indigo-600 hover:text-indigo-900">Edit</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          
          {/* Calendar view placeholder */}
          {selectedView === 'calendar' && (
            <div className="bg-white rounded-lg shadow p-6 h-full flex items-center justify-center">
              <p className="text-gray-500">Calendar view would be implemented here</p>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

export default ProjectManagementUI;