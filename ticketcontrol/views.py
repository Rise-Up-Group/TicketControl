from django.http import HttpResponse

from django.contrib.auth import login, logout, authenticate
from django.core.validators import validate_email
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.shortcuts import render, redirect
from django.http import HttpResponseRedirect
from .models import User, Ticket
from django.shortcuts import get_object_or_404
import logging
from django.http import Http404

logger = logging.getLogger(__name__)


def render_error(request, title, message):
    context = {'title': title, 'message': message}
    return render(request, "error.html", context)


def dashboard_view(request):
    return render(request, "dashboard.html")


def home_view(request):
    return render(request, "home.html")

##TODO: fix
def mytickets_view(request):
    context = {"dataset": Ticket.objects.all().filter()}
    return render(request, "ticket/manage.html", context)


def ticket_view(request, id):
    id = str(id) #TODO: no conversion

    context = {}
    try:
        ticket = get_object_or_404(Ticket, pk=id)
        context = {"ticket": ticket, "moderator": ticket.moderator.all()}
        return render(request, "ticket/detail.html", context)
    except Http404:
        return render_error(request, "404 - Not Found", "Ticket " + id + " Not Found")


def handler404(request, exception, template_name="error.html"):
    response = HttpResponse("404 page")#TODO: render template
    response.status_code = 404
    return response


def new_ticket_view(request):
    pass #TODO

def logout_view(request):
    logout(request)
    return redirect("home")

def login_view(request):
    context = {}
    if request.method == 'POST':
        username = str(request.POST['username'])
        password = request.POST['password']
        try:
            validate_email(username)
            try:
                user = User.objects.get(email=username)
            except ObjectDoesNotExist:
                user = None
        except ValidationError:
            try:
                user = User.objects.get(username=username)
            except ObjectDoesNotExist:
                user = None

        if user is not None and user.check_password(password):
            if user.is_active:
                login(request, user)
                return redirect("dashboard")
            else:
                context = {"error": "User is not activated"}
        else:
            context = {"error": "Wrong username or password"}
    return render(request, "user/login.html", context)

def add_user(email, firstname, lastname, username, password, role, isActive):
    # TODO: preview in javascrip and show to user
    # TODO: nickname has to be unique (possibly with db)
    if username == "":
        username = firstname[0:1] + ". " + lastname
    # Creates ticketcontrol.user; never create a BaseUser
    user = User.objects.create_user(username=username, password=password, email=email)
    user.first_name = firstname
    user.last_name = lastname
    user.role = role
    user.is_active = isActive
    user.save()
    return user

def update_user(id, email, firstname, lastname, username, password, role, isActive):
    user = User.objects.get(id=id)
    if user is not None:
        user.email = email
        user.first_name = firstname
        user.last_name = lastname
        user.username = username
        if password != "" and password is not None:
            user.set_password(password)
        if role is not None:
            user.role = role
        if isActive is not None:
            user.is_active = isActive
        user.save()
        return user
    return None

def delete_user(id):
    User.objects.get(id=id).delete(keep_parents=False)

def register_view(request):
    if request.method == 'POST':
        password = request.POST['password']
        passwordRetype = request.POST['password_retype']
        if password == passwordRetype:
            user = add_user(request.POST['email'], request.POST['firstname'], request.POST['lastname'], request.POST['username'], password, User.RoleChoices.USER, 1)
            login(request, user)
            return redirect("profile")
        else:
            # Should not happen anyway
            return render_error(request, "Passwords do not match", "")
    return render(request, "user/register.html")

def create_user_view(request):
    if (request.method == 'POST'):
        password = request.POST['password']
        passwordRetype = request.POST['password_retype']
        if password == passwordRetype:
            user = add_user(request.POST['email'], request.POST['firstname'], request.POST['lastname'], request.POST['username'], password, request.POST['role'], request.POST.get("is_active", False) == "on")
            login(request, user)
            return redirect("profile")
        else:
            # Should not happen anyway
            return render_error(request, "Passwords do not match", "")
    return render(request, "user/create.html", {"RoleChoices": User.RoleChoices})


def manage_users_view(request):
    return render(request, "user/manage.html")

def user_details_view(request, id):
    return render(request, "user/details.html")


def edit_user_view(request, id):
    if request.method == 'POST':
        password = request.POST['password']
        passwordRetype = request.POST['password_retype']
        if password == "" or password == passwordRetype:
            update_user(id, request.POST['email'], request.POST['firstname'], request.POST['lastname'], request.POST['username'], password, request.POST['role'], request.POST.get("is_active", False) == "on")
            return redirect("user_details", id=id)
        else:
            # Should not happen anyway
            return render_error(request, "Passwords do not match", "")
    return render(request, "user/edit.html", {"user": get_object_or_404(User, pk=id), "RoleChoices": User.RoleChoices})


def delete_user_view(request, id):
    if request.method == 'POST':
        delete_user(id)
        return redirect("manage_users")
    return render(request, "user/delete.html", {"user": get_object_or_404(User, pk=id)})


def profile_view(request):
    return render(request, "user/profile.html")