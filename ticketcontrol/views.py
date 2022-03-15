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
            user = User.objects.get(email=username)
        except ValidationError:
            try:
                user = User.objects.get(username=username)
            except ObjectDoesNotExist:
                user = None

        if user is not None and user.check_password(password):
            login(request, user)
            return redirect("dashboard")
        context = {'wrong_username_or_password': True}
    return render(request, "user/login.html", context)

def register_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        firstname = request.POST['firstname']
        lastname = request.POST['lastname']
        username = request.POST['username']
        # TODO: preview in javascrip and show to user
        # TODO: nickname has to be unique (possibly with db)
        if username == "":
            username = firstname[0:1] + ". " + lastname
        password = request.POST['password']
        password_retype = request.POST['password_retype']
        if password == password_retype:
            # Creates ticketcontrol.user; never create a BaseUser
            user = User.objects.create_user(username=username, password=password, email=email)
            user.first_name = firstname
            user.last_name = lastname
            user.save()
            login(request, user)
            return redirect("profile")
        else:
            # Should not happen anyway
            return render_error(request, "Passwords do not match", "")
    else:
        return render(request, "user/register.html")

def profile_view(request):
    return render(request, "user/profile.html")