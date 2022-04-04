from django.http import HttpResponse

from django.contrib.auth import login
from django.shortcuts import render
from .models import User, Ticket, Comment, Category
from django.shortcuts import get_object_or_404, get_list_or_404
import logging
from django.http import Http404

logger = logging.getLogger(__name__)


def render_error(request, title, message):
    context = {'title': title, 'message': message}
    return render(request, "error.html", context)


def dashboard_view(request):
    return render(request, "dashboard.html")


##TODO: fix
def mytickets_view(request):
    context = {"dataset": Ticket.objects.all().filter()}
    return render(request, "ticket/manage.html", context)


def ticket_view(request, id):
    id = str(id)  # TODO: no conversion

    context = {}
    try:
        ticket = get_object_or_404(Ticket, pk=id)
        try:
            comments = get_list_or_404(Comment, ticket_id=ticket.id)
            try:
                category = get_list_or_404(Category)
                context = {"ticket": ticket, "moderator": ticket.moderator.all(),
                           "participants": ticket.participating.all(), "comments": comments, "category": category}
                return render(request, "ticket/detail.html", context)
            except Http404:
                return render_error(request, "404 - Not Found", "Unable to load Category")
        except Http404:
            return render_error(request, "404 - Not Found", "Comments in Ticket " + id + " Not Found")

    except Http404:
        return render_error(request, "404 - Not Found", "Ticket " + id + " Not Found")


def handler404(request, exception, template_name="error.html"):
    response = HttpResponse("404 page")  # TODO: render template
    response.status_code = 404
    return response


def new_ticket_view(request):
    pass  # TODO


def register_view(request):
    if request.method == 'POST':
        email = request.POST['email']
        firstname = str(request.POST['firstname'])  # TODO: remove conversion if possible
        lastname = str(request.POST['lastname'])
        username = str(request.POST['username'])
        # TODO: preview in javascript and show to user
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
            return render(request, "dashboard.html")
        else:
            # Should not happen anyway
            return render_error(request, "Passwords do not match", "")
    else:
        return render(request, "registration/register.html")
