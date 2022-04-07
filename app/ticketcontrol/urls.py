"""ticketcontrol URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.contrib.auth.views import LoginView, LogoutView
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from .views import *

app_name="ticketcontrol"
urlpatterns = [
    # path('admin/', admin_view),
    # Ticket
    path('ticket/my', mytickets_view),
    path('ticket/<int:id>', ticket_view),
    path('ticket/<int:id>/comment/add', ticket_comment_add, name="add_comment_to_ticket"),
    path('ticket/new', ticket_new_view, name='create_ticket'),
    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),
    path('register/', register_view, name='register'),
    path('user/create', create_user_view, name='create_user'),
    path('user/<int:id>', user_details_view, name='user_details'),
    path('user/<int:id>/edit', edit_user_view, name='edit_user'),
    path('user/<int:id>/delete', delete_user_view, name='delete_user'),
    path('user/profile', profile_view, name='profile'),
    path('user/manage', manage_users_view, name='manage_users'),
    path('group/manage', manage_groups_view, name='manage_groups'),
    path('group/create', create_group_view, name='create_group'),
    path('group/<int:id>/delete', delete_group_view, name='delete_group'),
    path('group/<int:id>', edit_group_view, name='edit_group'),
    path('djangoadmin/', admin.site.urls),
    path('', dashboard_view, name='dashboard'),
    path('home/', home_view, name='home'),
]

handler404 = "ticketcontrol.views.handler404"

if settings.DEBUG:
    urlpatterns += static (
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT,
    )
