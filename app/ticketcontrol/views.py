import logging

from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required, permission_required
from django.core.exceptions import ValidationError, ObjectDoesNotExist
from django.db.utils import DatabaseError
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect, Http404, JsonResponse
from django.middleware.csrf import get_token
from django.core.validators import validate_email
from django.shortcuts import get_object_or_404, get_list_or_404
from django.shortcuts import render, redirect
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import send_mail

from .models import *
from .settings import EMAIL_HOST_USER

logger = logging.getLogger(__name__)


def render_error(request, title, message):
    context = {'title': title, 'message': message}
    return render(request, "error.html", context)


def dashboard_view(request):
    if request.user.is_authenticated:
        own_tickets = Ticket.objects.filter(owner=request.user.id)
        part_tickets = Ticket.objects.filter(participating=request.user.id).exclude(owner=request.user.id)
        context = {'tickets': {'own': own_tickets, 'part': part_tickets}}
        return render(request, "dashboard.html", context)
    else:
        return render(request, "home.html")


@login_required()
def mytickets_view(request):
    own_tickets = Ticket.objects.filter(owner=request.user.id)
    part_tickets = Ticket.objects.filter(participating=request.user.id).exclude(owner=request.user.id, moderator=request.user.id)
    mod_tickets = Ticket.objects.filter(moderator=request.user.id).exclude(owner=request.user.id)
    context = {'tickets': {'own': own_tickets, 'part': part_tickets, 'mod': mod_tickets}}
    return render(request, "ticket/manage.html", context)


@login_required()
def ticket_view(request, id):
    id = str(id)  # TODO: no conversion

    context = {}
    try:
        ticket = get_object_or_404(Ticket, pk=id)
        try:
            comments = get_list_or_404(Comment, ticket_id=ticket.id)
        except Http404:
            comments = None

        try:
            category = get_list_or_404(Category)
            context = {"ticket": ticket, "moderators": ticket.moderator.all(),
                       "participants": ticket.participating.all(), "comments": comments, "category": category}
            return render(request, "ticket/detail.html", context)
        except Http404:
            return render_error(request, "404 - Not Found", "Unable to load Category")
    except Http404:
        return render_error(request, "404 - Not Found", "Ticket " + id + " Not Found")


def handler404(request, exception, template_name="error.html"):
    response = HttpResponse("404 page")  # TODO: render template
    response.status_code = 404
    return response


def logout_view(request):
    logout(request)
    return redirect("/")


def login_view(request):
    error = ""
    next = request.GET.get("next", False)
    if next == False:
        next = request.POST.get("next", False)
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
            if user.is_active and user.email_confirmed:
                login(request, user)
                if next is not False:
                    return HttpResponseRedirect(next)
                return redirect("dashboard")
            else:
                error = "User is not activated or email address is not confirmed"
        else:
            error = "Wrong username or password"
    if request.user.is_authenticated:
        return redirect("dashboard")
    return render(request, "user/login.html", {"error": error, "next": next})


def register_view(request):
    if request.method == 'POST':
        password = request.POST['password']
        confirmPassword = request.POST['confirm_password']
        if password == confirmPassword:
            if len(password) < 8:
                return HttpResponse(status=411)
            if not User.objects.filter(email=request.POST['email']).exists() and not User.objects.filter(
                    username=request.POST['username']).exists():
                user = User.add_user("", request.POST['firstname'], request.POST['lastname'],
                                     request.POST['username'], password, groups=None, is_active=True,
                                     email_confirmed=False)
                user.new_email = request.POST['email']
                user.save()
                User.send_emailverification_mail(user, request)
                return render(request, "user/activate.html")
            else:
                return HttpResponse(status=409)
        else:
            # Should not happen anyway
            return render_error(request, "Passwords do not match", "")
    return render(request, "user/register.html")


def activate_user_view(request):
    if request.method == "POST":
        user = User.objects.get(id=request.POST['user-id'])
        token = request.POST['token']
        if account_activation_token.check_token(user, token):
            if not User.objects.filter(email=user.new_email).exists():
                if not user.email_confirmed:
                    user.email_confirmed = True
                    user.email = user.new_email
                    user.new_email = ""
                else:
                    user.email = user.new_email
                    user.new_email = ""
                user.save()
                return redirect("login")
            return HttpResponse(status=409)
        else:
            return HttpResponse(status=498)
    user = User.objects.get(id=request.GET['user-id'])
    return render(request, "user/activate.html", {"content_user": user, "token": request.GET['token']})


def user_passwordreset_view(request):
    if request.method == "POST":
        user = User.objects.get(id=request.POST['user-id'])
        token = request.POST['token']
        if password_reset_token.check_token(user, token):
            if request.POST['password'] == request.POST['confirm_password']:
                user.set_password(request.POST['password'])
                user.save()
                login(request, user)
                return redirect("dashboard")
            return render_error(request, "Passwords do not match", "")
        else:
            return HttpResponse(status=498)
    return render(request, "user/passwordreset.html",
                  {"content_user": User.objects.get(id=request.GET['user-id']), "token": request.GET['token']})


def user_passwordreset_request_view(request):
    if request.method == "POST":
        username = request.POST['username']
        try:
            validate_email(username)
            user = User.objects.get(email=username)
        except ValidationError:
            user = User.objects.get(username=username)
        user.send_passwordreset_mail(request)
        return render(request, "user/passwordreset_request.html", {"sent_email": True})
    return render(request, "user/passwordreset_request.html")


@permission_required("ticketcontrol.add_user")
def create_user_view(request):
    if (request.method == 'POST'):
        password = request.POST['password']
        if len(password) < 8:
            return HttpResponse(status=411)
        groups = None
        if request.user.has_perm("ticketcontrol.change_user_permission"):
            groups = request.POST.getlist("groups")
        if not User.objects.filter(email=request.POST['email']).exists() and not User.objects.filter(
                username=request.POST['username']).exists():
            User.add_user(request.POST['email'], request.POST['firstname'], request.POST['lastname'],
                          request.POST['username'], password, groups, request.POST.get("is_active", False) == "on", email_confirmed=True)
            return redirect("manage_users")
        else:
            return HttpResponse(status=409)
    return render(request, "user/create.html", {"groups": Group.objects.all(),
                                                "can_change_permission": request.user.has_perm(
                                                    "ticketcontrol.change_user_permission")})


@permission_required("ticketcontrol.view_user")
def manage_users_view(request):
    return render(request, "user/manage.html",
                  {"users": User.objects.all(), "can_create": request.user.has_perm("ticketcontrol.create_user"),
                   "can_change": request.user.has_perm("ticketcontrol.change_user"),
                   "can_delete": request.user.has_perm("ticketcontrol.delete_user")})


@login_required()
def user_details_view(request, id):
    if request.user.has_perm("ticketcontrol.view_user") or request.user.id == id:
        return render(request, "user/details.html", {"content_user": User.objects.get(id=id),
                                                     "can_change": request.user.has_perm(
                                                         "ticketcontrol.change_user") or request.user.id == id})
    return redirect("login")


@login_required()
def user_live_search(request, typed_username):
    some_users = User.objects.filter(username__contains=typed_username)[:10]
    res = []
    for user in some_users:
        newUser = {"username": user.username, "first_name": user.first_name, "last_name": user.last_name, "id": user.id}
        res.append(newUser)
    return JsonResponse(res, safe=False)  # It's ok. Disables typecheck for dict. Make sure to only pass an array


@login_required()
def edit_user_view(request, id):
    if request.user.has_perm("ticketcontrol.change_user") or request.user.id == id:
        if request.method == 'POST':
            password = request.POST['password']
            if password != "" and len(password) < 8:
                return HttpResponse(status=411)
            groups = None
            if request.user.has_perm("ticketcontrol.change_user_permission"):
                groups = request.POST.getlist("groups")
            user = User.objects.get(id=id)
            if user.username == request.POST['username'] or not User.objects.filter(
                    username=request.POST['username']).exists():
                user.update_user(None, request.POST['firstname'], request.POST['lastname'],
                                 request.POST['username'], password, groups,
                                 request.POST.get("is_active", False) == "on")
                if user.email != request.POST['email']:
                    if not User.objects.filter(email=request.POST['email']).exists():
                        if request.user.has_perm("ticketcontrol.change_user"):
                            user.email = request.POST['email']
                            user.save()
                        else:
                            user.update_user(email=request.POST['email'])
                            user.send_emailverification_mail(request)
                            return render(request, "user/activate.html")
                    else:
                        return HttpResponse(status=409)
                    return redirect("edit_user", id=id)
            else:
                return HttpResponse(status=409)
        user = get_object_or_404(User, pk=id)
        groups = []
        for group in user.groups.all():
            groups.append(group.id)
        return render(request, "user/edit.html",
                      {"content_user": user, "userGroups": groups, "groups": Group.objects.all(),
                       "can_change_permission": request.user.has_perm("ticketcontrol.change_user_permission"),
                       "can_change": True,
                       "can_delete": request.user.has_perm("ticketcontrol.delete_user") or request.user.id == id})
    return redirect("login")


@login_required()
def profile_view(request):
    return edit_user_view(request, request.user.id)


def unrestricted_delete_user_view(request, id):
    if request.method == 'POST':
        User.delete_user(id)
        return redirect("manage_users")


@permission_required("ticketcontrol.delete_user")
def restricted_delete_user_view(request, id):
    return unrestricted_delete_user_view(request, id)


@login_required()
def delete_user_view(request, id):
    if (request.user.id == id):
        return unrestricted_delete_user_view(request, id)
    return restricted_delete_user_view(request, id)


@permission_required("auth.view_group")
def manage_groups_view(request):
    return render(request, "user/group/manage.html",
                  {"groups": Group.objects.all().order_by("id"), "can_create": request.user.has_perm("ticketcontrol.create_user")})


@permission_required("auth.create_group")
def create_group_view(request):
    if request.method == 'POST':
        group = Group.objects.create(name=request.POST['name'])
        permissions = request.POST.getlist("permissions")
        allPermissions = Permission.objects.all()
        for permission in permissions:
            inAllPermissions = False
            for perm in allPermissions:
                if int(perm.perm.id) == int(permission):
                    inAllPermissions = True
            if inAllPermissions:
                group.permissions.add(permission)
        group.save()
        return redirect("manage_groups")
    return render(request, "user/group/create.html", {"permissions": Permission.objects.all()})


@permission_required("auth.view_group")
def edit_group_view(request, id):
    canEdit = request.user.has_perm("auth.change_group")
    group = get_object_or_404(Group, id=id)
    if request.method == 'POST' and canEdit:
        if group.name != "admin" and group.name != "moderator" and group.name != "user":
            group.name = request.POST['name']
        if group.name != "admin":  # admin is superuser anyway
            groupPermissions = group.permissions.all()
            permissions = request.POST.getlist("permissions")
            allPermissions = Permission.objects.all()
            for permission in groupPermissions:
                if not permission.id in permissions:
                    group.permissions.remove(permission.id)

            for permission in permissions:
                inGroupPermissions = False
                for perm in groupPermissions:
                    if perm.id == permission:
                        inGroupPermissions = True
                inAllPermissions = False
                for perm in allPermissions:
                    if int(perm.perm.id) == int(permission):
                        inAllPermissions = True
                if not inGroupPermissions and inAllPermissions:
                    group.permissions.add(permission)
            group.save()
            return redirect("manage_groups")
        return render_error(request, "Unable to edit group",
                            "Editing default group \"" + group.name + "\" is not allowed.")
    groupPermissions = []
    for permissionId in group.permissions.all().values_list("id", flat=True):
        groupPermissions.append(permissionId)
    return render(request, "user/group/edit.html",
                  {"group": group, "group_permissions": groupPermissions, "permissions": Permission.objects.all(),
                   "can_change": canEdit, "can_delete": request.user.has_perm(
                      "ticketcontrol.delete_group") and group.name != "admin" and group.name != "moderator" and group.name != "user"})


@permission_required("auth.delete_group")
def delete_group_view(request, id):
    group = Group.objects.get(id=id)
    if group.name == "admin" or group.name == "moderator" or group.name == "user":
        return render_error(request, "Unable to delete group",
                            "Deleting default group \"" + group.name + "\" is not allowed.")
    if request.method == 'POST':
        group.delete()
        return redirect("manage_groups")


@login_required()
def ticket_new_view(request):
    if request.method == 'POST':
        Ticket.add_ticket(request.POST["title"], request.POST["description"], User.objects.get(id=request.user.id),
                          Category.objects.get(id=request.POST["category"]))
        return redirect('/ticket/my')
    else:
        try:
            category = get_list_or_404(Category)
            context = {"category": category}
            return render(request, "ticket/new.html", context)
        except Http404:
            return render_error(request, "404 - Not Found", "Unable to load Category")


@login_required()
def ticket_comment_add(request, id):
    if request.method == 'POST':
        ticket = Ticket.objects.get(id=id)
        ticket.add_comment(request.POST["comment"], User.objects.get(id=request.user.id))
        return redirect('/ticket/' + str(id))
    return HttpResponse(status=400)


@login_required()
def ticket_participant_add(request, id, username=None):
    if request.method == "POST":
        if username == None:
            return HttpResponse(status=409)
        try:
            ticket = Ticket.objects.get(id=id)
            if request.user.id == ticket.owner.id or request.user.has_perm("ticketcontrol.change_ticket"):
                ticket.participating.add(User.objects.get(username=username))
                return HttpResponse(status=200)
            return HttpResponse(status=403)
        except ObjectDoesNotExist:
            return HttpResponse(status=404)
        except DatabaseError:
            return HttpResponse(status=409)
    return HttpResponse(get_token(request))


@permission_required("ticketcontrol.change_ticket")
def ticket_moderator_add(request, id, username=None):
    if request.method == "POST":
        if username == None:
            return HttpResponse(status=409)
        try:
            ticket = Ticket.objects.get(id=id)
            ticket.moderator.add(User.objects.get(username=username))
            return HttpResponse(status=200)
        except ObjectDoesNotExist:
            return HttpResponse(status=404)
        except DatabaseError:
            return HttpResponse(status=409)
    return HttpResponse(get_token(request))
