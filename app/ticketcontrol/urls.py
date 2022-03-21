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
    path('ticket/my', mytickets_view),
    path('ticket/<int:id>', ticket_view),
    # path('ticket/new', new_ticket_view),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('register/', register_view, name='register'),
    path('djangoadmin/', admin.site.urls),
    path('', dashboard_view, name='dashboard'),
]

handler404 = "ticketcontrol.views.handler404"

if settings.DEBUG:
    urlpatterns += static (
        settings.MEDIA_URL,
        document_root=settings.MEDIA_ROOT,
    )