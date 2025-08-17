"""
Core views for ECUre application.
"""

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from .models import UserProfile, AuditLog


def home(request):
    """Home page view."""
    return render(request, 'core/home.html')


@login_required
def dashboard(request):
    """User dashboard view."""
    context = {
        'user': request.user,
        'profile': getattr(request.user, 'profile', None),
    }
    return render(request, 'core/dashboard.html', context)


@login_required
def profile(request):
    """User profile view."""
    if request.method == 'POST':
        # Handle profile updates
        profile, created = UserProfile.objects.get_or_create(user=request.user)
        profile.organization = request.POST.get('organization', '')
        profile.role = request.POST.get('role', '')
        profile.phone = request.POST.get('phone', '')
        profile.save()
        
        # Log the action
        AuditLog.objects.create(
            user=request.user,
            action='SYSTEM_CONFIG',
            details={'action': 'profile_updated'},
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')
        )
        
        messages.success(request, 'Profile updated successfully!')
        return redirect('core:profile')
    
    context = {
        'user': request.user,
        'profile': getattr(request.user, 'profile', None),
    }
    return render(request, 'core/profile.html', context)
