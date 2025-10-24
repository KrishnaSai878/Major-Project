#!/usr/bin/env python3
"""
Admin Authentication and Authorization Decorators
Provides role-based access control for admin functionality
"""

from functools import wraps
from flask import request, jsonify, flash, redirect, url_for, abort, session, g, current_app
from flask_login import current_user, login_required
from datetime import datetime, timedelta
import json
import time
import re
import secrets
import hashlib
from database.models import AdminAuditLog, AdminRole, AdminUserRole, db

def log_admin_action(action, resource_type, resource_id=None, details=None, success=True, error_message=None):
    """Log admin actions for audit purposes"""
    try:
        if not current_user.is_authenticated:
            return
            
        audit_log = AdminAuditLog(
            admin_user_id=current_user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            action_details=json.dumps(details) if details else None,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')[:500],
            success=success,
            error_message=error_message
        )
        
        from database.models import db
        db.session.add(audit_log)
        db.session.commit()
    except Exception as e:
        # Don't let logging failures break the application
        print(f"Failed to log admin action: {e}")

def generate_csrf_token():
    """Generate CSRF token for admin forms"""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']


def validate_csrf_token(token):
    """Validate CSRF token"""
    return token == session.get('csrf_token')


def rate_limit_admin_requests(max_requests=10, time_window=60):
    """
    Rate limiting decorator for admin requests
    max_requests: maximum number of requests allowed
    time_window: time window in seconds
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = current_user.id if current_user.is_authenticated else request.remote_addr
            key = f"rate_limit_admin:{user_id}"
            
            now = time.time()
            if not hasattr(g, 'rate_limit_requests'):
                g.rate_limit_requests = {}
            
            if key not in g.rate_limit_requests:
                g.rate_limit_requests[key] = []
            
            # Clean old requests
            g.rate_limit_requests[key] = [
                timestamp for timestamp in g.rate_limit_requests[key]
                if now - timestamp < time_window
            ]
            
            # Check if limit exceeded
            if len(g.rate_limit_requests[key]) >= max_requests:
                log_admin_action(
                    'RATE_LIMIT_EXCEEDED',
                    'admin_request',
                    details={'endpoint': request.endpoint, 'user_id': user_id},
                    success=False,
                    error_message='Rate limit exceeded'
                )
                return jsonify({'error': 'Rate limit exceeded. Please try again later.'}), 429
            
            # Add current request
            g.rate_limit_requests[key].append(now)
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_admin_input(schema):
    """
    Input validation decorator for admin endpoints
    schema: dict with field names and validation rules
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            data = request.get_json() if request.is_json else request.form
            errors = {}
            
            for field, rules in schema.items():
                value = data.get(field, '')
                
                # Required validation
                if rules.get('required') and not value:
                    errors[field] = f'{field} is required'
                    continue
                
                # Skip further validation if field is empty and not required
                if not value and not rules.get('required'):
                    continue
                
                # Type validation
                if rules.get('type') == 'email':
                    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
                    if not re.match(email_pattern, value):
                        errors[field] = f'{field} must be a valid email address'
                
                elif rules.get('type') == 'integer':
                    try:
                        int(value)
                    except (ValueError, TypeError):
                        errors[field] = f'{field} must be a valid integer'
                
                elif rules.get('type') == 'boolean':
                    if value not in ['true', 'false', True, False]:
                        errors[field] = f'{field} must be a boolean value'
                
                # Length validation
                if rules.get('min_length') and len(str(value)) < rules['min_length']:
                    errors[field] = f'{field} must be at least {rules["min_length"]} characters'
                
                if rules.get('max_length') and len(str(value)) > rules['max_length']:
                    errors[field] = f'{field} must not exceed {rules["max_length"]} characters'
                
                # Pattern validation
                if rules.get('pattern'):
                    if not re.match(rules['pattern'], str(value)):
                        errors[field] = rules.get('pattern_message', f'{field} format is invalid')
                
                # Custom validation function
                if rules.get('custom_validator'):
                    try:
                        rules['custom_validator'](value)
                    except ValueError as e:
                        errors[field] = str(e)
            
            if errors:
                log_admin_action(
                    'INPUT_VALIDATION_FAILED',
                    'admin_request',
                    details={'errors': errors, 'endpoint': request.endpoint},
                    success=False,
                    error_message='Input validation failed'
                )
                return jsonify({'errors': errors}), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def admin_required(f):
    """Decorator to require admin role for a route"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            log_admin_action(
                action='UNAUTHORIZED_ACCESS_ATTEMPT',
                resource_type='ADMIN_AREA',
                success=False,
                error_message='Non-admin user attempted to access admin area'
            )
            if request.is_json:
                return jsonify({'error': 'Admin access required'}), 403
            else:
                flash('Admin access required', 'error')
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_permission_required(permission):
    """Decorator to require specific admin permission"""
    def decorator(f):
        @wraps(f)
        @admin_required
        def decorated_function(*args, **kwargs):
            if not has_admin_permission(current_user, permission):
                log_admin_action(
                    action='INSUFFICIENT_PERMISSIONS',
                    resource_type='ADMIN_AREA',
                    success=False,
                    error_message=f'User lacks required permission: {permission}'
                )
                if request.is_json:
                    return jsonify({'error': f'Insufficient permissions. Required: {permission}'}), 403
                else:
                    flash(f'Insufficient permissions. Required: {permission}', 'error')
                    return redirect(url_for('admin_users'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def has_admin_permission(user, permission):
    """Check if user has specific admin permission"""
    if not user.is_authenticated or user.role != 'admin':
        return False
    
    try:
        # Get all active roles for the user
        user_roles = AdminUserRole.query.filter_by(
            user_id=user.id, 
            is_active=True
        ).all()
        
        for user_role in user_roles:
            if user_role.expires_at and user_role.expires_at < datetime.utcnow():
                continue  # Skip expired roles
                
            role = AdminRole.query.filter_by(
                id=user_role.role_id, 
                is_active=True
            ).first()
            
            if role and role.has_permission(permission):
                return True
                
        return False
    except Exception as e:
        print(f"Error checking admin permissions: {e}")
        return False

def get_admin_permissions(user):
    """Get all permissions for an admin user"""
    if not user.is_authenticated or user.role != 'admin':
        return []
    
    permissions = set()
    try:
        user_roles = AdminUserRole.query.filter_by(
            user_id=user.id, 
            is_active=True
        ).all()
        
        for user_role in user_roles:
            if user_role.expires_at and user_role.expires_at < datetime.utcnow():
                continue
                
            role = AdminRole.query.filter_by(
                id=user_role.role_id, 
                is_active=True
            ).first()
            
            if role:
                role_perms = role.get_permissions()
                permissions.update([perm for perm, value in role_perms.items() if value])
                
        return list(permissions)
    except Exception as e:
        print(f"Error getting admin permissions: {e}")
        return []

def rate_limit_admin_requests(max_requests=100, window_minutes=60):
    """Rate limiting decorator for admin requests"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({'error': 'Authentication required'}), 401
                
            # Simple rate limiting using session (for production, use Redis or similar)
            from flask import session
            import time
            
            key = f'admin_rate_limit_{current_user.id}'
            now = time.time()
            window_seconds = window_minutes * 60
            
            # Get or initialize request history
            request_history = session.get(key, [])
            
            # Remove old requests outside the window
            request_history = [
                timestamp for timestamp in request_history 
                if now - timestamp < window_seconds
            ]
            
            # Check if limit exceeded
            if len(request_history) >= max_requests:
                log_admin_action(
                    action='RATE_LIMIT_EXCEEDED',
                    resource_type='ADMIN_AREA',
                    success=False,
                    error_message=f'Rate limit exceeded: {max_requests} requests per {window_minutes} minutes'
                )
                return jsonify({
                    'error': f'Rate limit exceeded. Maximum {max_requests} requests per {window_minutes} minutes.'
                }), 429
            
            # Add current request
            request_history.append(now)
            session[key] = request_history
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def validate_admin_input(validation_rules):
    """Input validation decorator for admin operations"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if request.method in ['POST', 'PUT', 'PATCH']:
                data = request.get_json() if request.is_json else request.form
                # Include route params as valid sources for required fields
                view_args = getattr(request, 'view_args', {}) or {}
                
                errors = []
                for field, rules in validation_rules.items():
                    value = data.get(field)
                    if value is None and field in view_args:
                        value = view_args.get(field)
                    
                    if rules.get('required') and not value:
                        errors.append(f'{field} is required')
                    
                    if value and rules.get('type') == 'email':
                        import re
                        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', value):
                            errors.append(f'{field} must be a valid email address')
                    
                    if value and rules.get('min_length') and len(str(value)) < rules['min_length']:
                        errors.append(f'{field} must be at least {rules["min_length"]} characters')
                    
                    if value and rules.get('max_length') and len(str(value)) > rules['max_length']:
                        errors.append(f'{field} must not exceed {rules["max_length"]} characters')
                
                if errors:
                    log_admin_action(
                        action='INVALID_INPUT',
                        resource_type='ADMIN_AREA',
                        success=False,
                        error_message='; '.join(errors)
                    )
                    if request.is_json:
                        return jsonify({'errors': errors}), 400
                    else:
                        for error in errors:
                            flash(error, 'error')
                        return redirect(request.referrer or url_for('admin_users'))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator