# Admin Dashboard Documentation

## Overview

The Admin Dashboard provides comprehensive administrative capabilities for managing the NGO Connect platform. It includes user management, analytics, audit logging, system settings, and security features.

## Features

### 1. Dashboard Overview (`/admin/dashboard`)
- **Purpose**: Main administrative dashboard with key metrics
- **Features**:
  - User statistics (total users, active users, new registrations)
  - Event statistics (total events, upcoming events)
  - Donation statistics (total donations, recent donations)
  - NGO statistics (total NGOs, active NGOs)
  - Quick action buttons for common tasks

### 2. User Management (`/admin/users`)
- **Purpose**: Manage platform users (volunteers, NGOs, donors)
- **Features**:
  - User listing with search and filtering
  - User role management
  - Account status management (activate/deactivate)
  - User verification
  - User deletion (with safeguards)
  - Bulk user export to CSV
  - Add new users

### 3. Analytics Dashboard (`/admin/analytics`)
- **Purpose**: Platform analytics and insights
- **Features**:
  - User registration trends
  - User role distribution
  - Platform activity metrics
  - Top performing NGOs
  - Key Performance Indicators (KPIs)
  - Interactive charts using Chart.js

### 4. Audit Logging (`/admin/audit-logs`)
- **Purpose**: Track administrative actions for security and compliance
- **Features**:
  - Complete audit trail of admin actions
  - Filter by admin user, action type, and date range
  - Export audit logs to CSV
  - Clear old audit logs (90+ days)
  - Action details (timestamp, admin, IP address, user agent)

### 5. System Settings (`/admin/settings`)
- **Purpose**: Configure platform settings
- **Features**:
  - General settings (site name, email, maintenance mode)
  - Security settings (max login attempts, session timeout)
  - File upload settings (max file size, allowed types)
  - User registration settings
  - Email configuration

## Security Features

### Authentication & Authorization
- **Admin-only access**: All admin routes require admin privileges
- **Role-based permissions**: Different admin levels with specific permissions
- **Login required**: Must be logged in to access any admin functionality

### Security Measures

#### 1. CSRF Protection
- **Implementation**: CSRF tokens for all state-changing operations
- **Usage**: Included in all forms and AJAX requests
- **Configuration**: Automatically generated and validated

#### 2. Rate Limiting
- **Dashboard access**: 30 requests per 60-second window
- **User management**: 50 requests per 60-second window
- **User actions**: 20 requests per 60-second window
- **User deletion**: 10 requests per 60-second window
- **User creation**: 15 requests per 60-second window

#### 3. Input Validation
- **User ID validation**: Integer validation for user operations
- **Email validation**: Proper email format validation
- **Role validation**: Restricted to valid roles (ngo, volunteer, donor, admin)
- **Length constraints**: Maximum length limits on all text inputs
- **Regex patterns**: Custom validation patterns for specific fields

#### 4. Audit Logging
- **Action tracking**: All admin actions are logged
- **Details captured**: User, action, timestamp, IP address, user agent
- **Retention**: 90-day retention policy with cleanup functionality

#### 5. Security Headers
- **X-Frame-Options**: Prevents clickjacking
- **X-Content-Type-Options**: Prevents MIME-type sniffing
- **X-XSS-Protection**: XSS protection
- **Content-Security-Policy**: Content security policy

## File Structure

```
project/
├── app.py                          # Main Flask application with admin routes
├── admin_decorators.py            # Admin-specific decorators and utilities
├── templates/
│   └── admin/
│       ├── admin_base.html        # Base template for admin pages
│       ├── admin_dashboard.html   # Main dashboard template
│       ├── admin_users.html       # User management template
│       ├── admin_analytics.html   # Analytics dashboard template
│       ├── admin_audit_logs.html  # Audit logs template
│       └── admin_settings.html    # Settings template
├── static/
│   └── js/
│       └── admin.js               # Admin-specific JavaScript functionality
└── test_scripts/
    ├── test_admin_dashboard.py    # Functional tests
    ├── validate_security.py       # Security validation tests
    ├── test_performance.py        # Performance tests
    └── run_all_tests.py           # Test runner
```

## Installation & Setup

### Prerequisites
- Python 3.7+
- Flask and required dependencies
- Database (MySQL/PostgreSQL)

### Installation Steps

1. **Install dependencies**:
   ```bash
   pip install flask flask-sqlalchemy flask-login requests
   ```

2. **Create admin user**:
   ```python
   # In Python shell or script
   from app import app, db, User
   with app.app_context():
       admin = User(
           first_name='Admin',
           last_name='User',
           email='admin@example.com',
           role='admin'
       )
       admin.set_password('admin123')
       db.session.add(admin)
       db.session.commit()
   ```

3. **Start the application**:
   ```bash
   python app.py
   ```

4. **Access admin dashboard**:
   - Navigate to `http://localhost:5000/admin/dashboard`
   - Login with admin credentials

## Usage Guide

### Dashboard Navigation
1. **Login**: Access `/login` with admin credentials
2. **Dashboard**: Main overview at `/admin/dashboard`
3. **User Management**: Manage users at `/admin/users`
4. **Analytics**: View analytics at `/admin/analytics`
5. **Audit Logs**: Review logs at `/admin/audit-logs`
6. **Settings**: Configure system at `/admin/settings`

### User Management Workflow
1. **View Users**: Navigate to `/admin/users`
2. **Search Users**: Use search bar to find specific users
3. **Filter Users**: Filter by role or status
4. **Edit User**: Click on user actions to modify
5. **Verify User**: Click verify button for unverified users
6. **Toggle Status**: Activate/deactivate user accounts
7. **Delete User**: Remove users (admins cannot be deleted)
8. **Add User**: Use "Add User" button for new registrations

### Analytics Usage
1. **View Analytics**: Navigate to `/admin/analytics`
2. **Key Metrics**: Review summary statistics
3. **Charts**: Interactive charts for trends
4. **Top NGOs**: View most active organizations
5. **KPIs**: Monitor platform performance indicators

### Audit Log Management
1. **View Logs**: Navigate to `/admin/audit-logs`
2. **Filter Logs**: Filter by admin, action, or date
3. **Export Logs**: Download logs as CSV
4. **Clear Logs**: Remove logs older than 90 days

### Settings Configuration
1. **Access Settings**: Navigate to `/admin/settings`
2. **General Settings**: Configure site name, email, modes
3. **Security Settings**: Set login attempts, session timeout
4. **File Settings**: Configure upload limits and types
5. **Save Changes**: Click "Save Settings" to apply

## API Endpoints

### Dashboard Endpoints
- `GET /admin/dashboard` - Main dashboard
- `GET /admin/analytics` - Analytics page
- `GET /admin/analytics/data` - Analytics data (JSON)

### User Management Endpoints
- `GET /admin/users` - User list page
- `POST /admin/users/<id>/toggle-status` - Toggle user status
- `POST /admin/users/<id>/verify` - Verify user
- `POST /admin/users/<id>/delete` - Delete user
- `POST /admin/add-user` - Create new user
- `GET /admin/users/export` - Export users to CSV

### Audit Log Endpoints
- `GET /admin/audit-logs` - Audit logs page
- `GET /admin/audit-logs/export` - Export audit logs
- `POST /admin/audit-logs/clear` - Clear old logs

### Settings Endpoints
- `GET /admin/settings` - Settings page
- `POST /admin/settings/update` - Update settings

## Testing

### Running Tests
```bash
# Run all tests
python run_all_tests.py

# Run individual test suites
python test_admin_dashboard.py    # Functional tests
python validate_security.py       # Security validation
python test_performance.py        # Performance tests
```

### Test Coverage
- **Functional Tests**: All admin features and workflows
- **Security Tests**: CSRF, XSS, SQL injection, authentication
- **Performance Tests**: Response times, concurrent load, memory usage

## Security Best Practices

### For Administrators
1. **Strong Passwords**: Use complex, unique passwords
2. **Regular Updates**: Keep passwords updated
3. **Session Management**: Log out when finished
4. **Access Control**: Only grant admin access when necessary
5. **Audit Review**: Regularly review audit logs

### For Developers
1. **Input Validation**: Always validate and sanitize inputs
2. **CSRF Protection**: Use CSRF tokens for state changes
3. **Rate Limiting**: Implement appropriate rate limits
4. **Error Handling**: Don't expose sensitive information
5. **Logging**: Log all administrative actions
6. **Testing**: Regular security testing

## Troubleshooting

### Common Issues

#### Cannot Access Admin Dashboard
- **Check**: Ensure user has admin role
- **Check**: Verify login status
- **Check**: Review authentication decorators

#### Rate Limiting Errors
- **Issue**: Too many requests in short time
- **Solution**: Wait for rate limit window to reset
- **Check**: Review rate limit configuration

#### CSRF Token Errors
- **Issue**: Form submission fails with CSRF error
- **Solution**: Ensure CSRF token is included in forms
- **Check**: Verify CSRF token generation

#### Database Connection Issues
- **Check**: Database configuration
- **Check**: Database server status
- **Check**: Connection string validity

### Performance Issues
- **Slow Dashboard**: Check database query optimization
- **High Memory Usage**: Review memory leak testing
- **Slow Analytics**: Consider caching for analytics data

## Maintenance

### Regular Tasks
1. **Review Audit Logs**: Weekly review of admin actions
2. **User Management**: Regular cleanup of inactive users
3. **Performance Monitoring**: Monitor response times
4. **Security Updates**: Keep dependencies updated
5. **Backup**: Regular database backups

### Cleanup Tasks
1. **Audit Log Cleanup**: Clear logs older than 90 days
2. **Session Cleanup**: Remove expired sessions
3. **Temp File Cleanup**: Remove temporary files

## Support

For issues and questions:
1. Check this documentation
2. Review test results
3. Check server logs
4. Run validation scripts
5. Review security scan results

## Version History

- **v1.0.0**: Initial admin dashboard implementation
- **v1.1.0**: Added security measures (CSRF, rate limiting)
- **v1.2.0**: Added comprehensive testing suite
- **v1.3.0**: Performance optimization and analytics