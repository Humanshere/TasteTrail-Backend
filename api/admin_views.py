"""
Lightweight HTML Admin Panel (server-rendered)
Allows admin to login, list users, and edit user properties in MongoDB.

Auth model: simple session using ADMIN_SECRET from environment.
This avoids relying on Django ORM users since project uses MongoDB directly.
"""

import os
from bson import ObjectId
from django.shortcuts import render, redirect
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.contrib import messages
from django.utils.decorators import method_decorator
from django.http import HttpRequest, HttpResponse, HttpResponseForbidden
from django.urls import reverse

from .mongo_db import users_collection
from .validators import UsernameValidator, RoleValidator
from .utils import PasswordHasher


ADMIN_SESSION_KEY = 'admin_authenticated'
ADMIN_SECRET = os.getenv('ADMIN_SECRET')


def _require_admin(request: HttpRequest):
    return request.session.get(ADMIN_SESSION_KEY, False) is True


@csrf_protect
@require_http_methods(["GET", "POST"])
def admin_login(request: HttpRequest):
    if request.method == 'GET':
        if _require_admin(request):
            return redirect('admin_users_list')
        return render(request, 'admin_panel/login.html')

    # POST
    secret = request.POST.get('secret', '').strip()
    if not ADMIN_SECRET:
        messages.error(request, 'ADMIN_SECRET is not configured on the server.')
        return render(request, 'admin_panel/login.html')

    if secret == ADMIN_SECRET:
        request.session[ADMIN_SESSION_KEY] = True
        messages.success(request, 'Logged in to Admin Panel.')
        return redirect('admin_users_list')
    else:
        messages.error(request, 'Invalid secret.')
        return render(request, 'admin_panel/login.html')


@require_http_methods(["POST"])  # simple action
def admin_logout(request: HttpRequest):
    request.session.flush()
    messages.info(request, 'Logged out of Admin Panel.')
    return redirect('admin_login')


@require_http_methods(["GET"])  # list page
def admin_users_list(request: HttpRequest):
    if not _require_admin(request):
        return redirect('admin_login')

    q = request.GET.get('q', '').strip()
    query = {}
    if q:
        # search by email or username contains
        query = {
            '$or': [
                {'email': {'$regex': q, '$options': 'i'}},
                {'username': {'$regex': q, '$options': 'i'}},
            ]
        }
    users = list(users_collection.find(query).sort('created_at', -1))

    # transform id strings for template
    for u in users:
        u['id'] = str(u['_id'])

    return render(request, 'admin_panel/users_list.html', {
        'users': users,
        'q': q,
    })


@csrf_protect
@require_http_methods(["GET", "POST"])  # edit page
def admin_user_edit(request: HttpRequest, user_id: str):
    if not _require_admin(request):
        return redirect('admin_login')

    try:
        oid = ObjectId(user_id)
    except Exception:
        messages.error(request, 'Invalid user id.')
        return redirect('admin_users_list')

    user = users_collection.find_one({'_id': oid})
    if not user:
        messages.error(request, 'User not found.')
        return redirect('admin_users_list')

    if request.method == 'GET':
        # prepare values
        context = {
            'user': {
                'id': str(user['_id']),
                'email': user.get('email', ''),
                'username': user.get('username', ''),
                'role': user.get('role', 'user'),
                'is_active': user.get('is_active', True),
                'is_verified': user.get('is_verified', False),
            }
        }
        return render(request, 'admin_panel/user_edit.html', context)

    # POST -> update
    username = request.POST.get('username', '').strip()
    role = request.POST.get('role', 'user').strip().lower()
    is_active = True if request.POST.get('is_active') == 'on' else False
    is_verified = True if request.POST.get('is_verified') == 'on' else False
    new_password = request.POST.get('new_password', '').strip()

    # validate username/role
    ok, err = UsernameValidator.validate(username)
    if not ok:
        messages.error(request, err)
        return redirect(reverse('admin_user_edit', args=[user_id]))

    ok, err = RoleValidator.validate(role)
    if not ok:
        messages.error(request, err)
        return redirect(reverse('admin_user_edit', args=[user_id]))

    # ensure username unique (if changed)
    existing = users_collection.find_one({'username': username, '_id': {'$ne': oid}})
    if existing:
        messages.error(request, 'Username already in use by another user.')
        return redirect(reverse('admin_user_edit', args=[user_id]))

    update_doc = {
        'username': username,
        'role': role,
        'is_active': is_active,
        'is_verified': is_verified,
    }

    if new_password:
        # optional: reset password
        update_doc['password'] = PasswordHasher.hash_password(new_password)

    users_collection.update_one({'_id': oid}, {'$set': update_doc})
    messages.success(request, 'User updated successfully.')
    return redirect('admin_users_list')
