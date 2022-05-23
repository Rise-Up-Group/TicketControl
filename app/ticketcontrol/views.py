import json
import logging
import os

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
from django.conf import settings
from django.views.static import serve

from .models import *

logger = logging.getLogger(__name__)


def render_error(request, title, message):
    context = {'title': title, 'message': message}
    return render(request, "error.html", context)


def dashboard_view(request):
    if request.user.is_authenticated:
        own_tickets = Ticket.objects.filter(owner=request.user.id, hidden=False)
        part_tickets = Ticket.objects.filter(participating=request.user.id, hidden=False).exclude(owner=request.user.id)
        context = {'tickets': {'own': own_tickets, 'part': part_tickets}}
        return render(request, "dashboard.html", context)
    else:
        return render(request, "home.html")


@login_required()
def mytickets_view(request):
    own_tickets = Ticket.objects.filter(owner=request.user.id, hidden=False)
    part_tickets = Ticket.objects.filter(participating=request.user.id).exclude(owner=request.user.id, moderator=request.user.id, hidden=False)
    mod_tickets = Ticket.objects.filter(moderator=request.user.id).exclude(owner=request.user.id, hidden=False)
    context = {'tickets': {'own': own_tickets, 'part': part_tickets, 'mod': mod_tickets}}
    return render(request, "ticket/manage.html", context)


@login_required()
def ticket_view(request, id):
    id = str(id)  # TODO: no conversion

    context = {}
    try:
        ticket = get_object_or_404(Ticket, pk=id)
        if ticket.hidden and not request.user.has_perm("ticketcontrol.unhide_ticket"):
            return render_error(request, "404 - Not Found", "Ticket " + id + " Not Found")
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
                          request.POST['username'], password, groups, request.POST.get("is_active", False) == "on",
                          email_confirmed=True)
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
                       "can_change_permission": request.user.has_perm(
                           "ticketcontrol.change_user_permission"),
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
        user = User.objects.get(id=request.user.id)
        ticket = Ticket.add_ticket(request.POST["title"], request.POST["description"], user,
                                   Category.objects.get(id=request.POST["category"]), request.POST["location"])
        for attachment_id in request.POST.getlist("attachments"):
            attachment = Attachment.objects.get(id=attachment_id)
            if attachment.user.id == request.user.id:
                ticket.attachment_set.add(attachment)
        ticket.save()
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
        user = User.objects.get(id=request.user.id)
        comment = ticket.add_comment(request.POST["comment"], user)
        for attachment_id in request.POST.getlist("attachments"):
            attachment = Attachment.objects.get(id=attachment_id)
            if attachment.user.id == request.user.id:
                comment.attachment_set.add(attachment)
        comment.save()
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
            if ticket.status == "Unassigned":
                ticket.set_status("Assigned")
                ticket.save()
            return HttpResponse(status=200)
        except ObjectDoesNotExist:
            return HttpResponse(status=404)
        except DatabaseError:
            return HttpResponse(status=409)
    return HttpResponse(get_token(request))


def attachment_access_control(request, id, name=None):
    if name is None:
        name = str(id)
    attachment = Attachment.objects.get(id=id)
    authorized = False
    if request.user.id == attachment.user.id:
        authorized = True
    elif attachment.ticket is not None and request.user.id == attachment.ticket.owner.id:
        authorized = True
    elif attachment.comment is not None and request.user.id == attachment.comment.user.id:
        authorized = True
    elif request.user.has_perm("ticketcontrol.view_attachment"):
        authorized = True
    else:
        for participant in attachment.ticket.participating.all():
            if request.user.id == participant.id:
                authorized = True
        if not authorized:
            for moderator in attachment.ticket.moderator.all():
                if request.user.id == moderator.id:
                    authorized = True
    if authorized:
        if not settings.DEBUG:
            response = HttpResponse()
            # Content-type will be detected by nginx
            del response['Content-Type']
            response['X-Accel-Redirect'] = '/serve_attachment/' + str(id)
            response['Content-Disposition'] = 'attachment;filename="' + name + '"'
            return response
        else:
            response = serve(request, str(id), document_root="uploads")
            response['Content-Disposition'] = 'attachment;filename="' + name + '"'
            return response
    else:
        return HttpResponse(status=403)


def upload_attachment(request):
    if request.method == "POST":
        file = request.FILES['attachment']
        attachment = Attachment.objects.create(filename=file.name, size=file.size, ticket=None, comment=None,
                                               user=User.objects.get(id=request.user.id))
        with open("uploads/" + str(attachment.id), "wb+") as destination:
            for chunk in file.chunks():
                destination.write(chunk)
        if request.POST.get("ticket"):
            ticket = Ticket.objects.get(id=request.POST['ticket'])
            if request.user.id == ticket.owner.id or request.user.has_perm("ticketcontrol.add_attachment"):
                attachment.ticket = ticket
        elif request.POST.get("comment"):
            comment = Comment.objects.get(id=request.POST['comment'])
            if request.user.id == comment.user.id or request.user.has_perm("ticketcontrol.add_attachment"):
                attachment.comment = comment
        attachment.save()
        return HttpResponse(str(attachment.id))


def delete_attachment(request, id):
    if request.method == "POST":
        attachment = Attachment.objects.get(id=id)
        authorized = False
        if request.user.id == attachment.user.id or request.user.has_perm("ticketcontrol.delete_attachment"):
            authorized = True
        elif attachment.ticket is not None and request.user.id == attachment.ticket.owner.id:
            authorized = True
        elif attachment.comment is not None and request.user.id == attachment.comment.user.id:
            authorized = True
        if authorized:
            os.remove("uploads/" + str(id))
            attachment.delete()
            return HttpResponse(status=200)

          
@permission_required("ticketcontrol.change_ticket")
def ticket_status_update(request, id):
    if request.method == "POST":
        try:
            ticket = Ticket.objects.get(id=id)
            ticket.set_status(request.POST['status_choice'])
            return redirect("ticket_view", id=id)
        except ObjectDoesNotExist:
            return HttpResponse(status=404)
        except DatabaseError:
            return HttpResponse(status=409)
    return HttpResponse(get_token(request))


def settings_view(request):
    if request.user.is_superuser:
        settings_file = open("settings/settings.json")
        settings_json = json.load(settings_file)
        settings_file.close()
        if request.method == "POST":
            general = settings_json['general']
            general['contact_email'] = request.POST['general.contact-email']
            general['allow_location'] = request.POST.get("general.allow-location", False) == "on"
            general['force_location'] = request.POST.get("general.force-location", False) == "on"
            email_server = settings_json['email_server']
            email_server['smtp_host'] = request.POST['email-server.smtp-host']
            email_server['smtp_port'] = int(request.POST['email-server.smtp-port'])
            email_server['smtp_use_tls'] = request.POST.get("email-server.smtp-use-tls", False) == "on"
            email_server['smtp_use_ssl'] = request.POST.get("email-server.smtp-use-ssl", False) == "on"
            email_server['smtp_user'] = request.POST['email-server.smtp-user']
            if request.POST['email-server.smtp-password'] is not None and request.POST['email-server.smtp-password'] != "":
                email_server['smtp_password'] = request.POST['email-server.smtp-password']

            content = settings_json['content']
            content['frontpage'] = request.POST['content.frontpage']
            content['half_page'] = request.POST['content.half-page']
            content['imprint'] = request.POST['content.imprint']

            register = settings_json['register']
            register['allow_custom_nickname'] = request.POST.get("register.allow-custom-nickname", False) == "on"
            register['email_whitelist_enable'] = request.POST.get("register.email-whitelist-enable", False) == "on"
            register['email_whitelist'] = []
            for entry in request.POST.getlist('register.email-whitelist'):
                register['email_whitelist'].append(entry)

            legal = settings_json['legal']
            legal['privacy_and_policy'] = request.POST['legal.privacy-and-policy']

            settings_file = open("settings/settings.json", "w")
            json.dump(settings_json, settings_file)
            settings_file.close()

            if request.POST.get('restart-server', False) == "on":
                os.system("/sbin/reboot")

        return render(request, "settings.html", {"settings": settings_json})
    else:
        return HttpResponse(status=403)


@permission_required("ticketcontrol.add_category")
def create_category_view(request):
    if request.method == "POST":
        Category.objects.create(name = request.POST['name'], color=request.POST['color'].strip("#"))
        return redirect("manage_categories")
    else:
        return render(request, "category/create.html")

@permission_required("ticketcontrol.view_category")
def edit_category_view(request, id):
    category = Category.objects.get(id=id)
    if request.method == "POST":
        if request.user.has_perm("ticketcontrol.edit_category"):
            category.name = request.POST['name']
            category.color = request.POST['color'].strip("#")
            category.save()
            return redirect("manage_categories")
        else:
            return HttpResponse(status=403)
    return render(request, "category/edit.html", {"category": category,
                                                  "can_change": request.user.has_perm("ticketcontrol.change_category"),
                                                  "can_delete": request.user.has_perm("ticketcontrol.delete_category")})


@permission_required("ticketcontrol.delete_category")
def delete_category_view(request, id):
    if request.method == "POST":
        category = Category.objects.get(id=id)
        category.delete()
        return redirect("manage_categories")
    else:
        return HttpResponse(status=409)


@permission_required("ticketcontrol.view_category")
def manage_categories_view(request):
    return render(request, "category/manage.html",
                  {"categories": Category.objects.all(), "can_create": request.user.has_perm("ticketcontrol.create_category")})


@permission_required("ticketcontrol.hide_ticket")
def ticket_hide(request, id):
    if request.method == "POST":
        try:
            ticket = Ticket.objects.get(id=id)
            ticket.set_hidden(True)
            return redirect("dashboard")
        except ObjectDoesNotExist:
            return HttpResponse(status=404)
        except DatabaseError:
            return HttpResponse(status=409)
    return HttpResponse(get_token(request))


@permission_required("ticketcontrol.unhide_ticket")
def ticket_unhide(request, id):
    if request.method == "POST":
        try:
            ticket = Ticket.objects.get(id=id)
            ticket.set_hidden(False)
            return redirect("ticket_view", id=id)
        except ObjectDoesNotExist:
            return HttpResponse(status=404)
        except DatabaseError:
            return HttpResponse(status=409)
    return HttpResponse(get_token(request))


@permission_required("ticketcontrol.delete_ticket")
def ticket_delete(request, id):
    if request.method == "POST":
        try:
            ticket = Ticket.objects.get(id=id)
            ticket.delete()
            return redirect("dashboard")
        except ObjectDoesNotExist:
            return HttpResponse(status=404)
        except DatabaseError:
            return HttpResponse(status=409)

def ticket_info_update(request, id):
    if request.method == "POST":
        try:
            ticket = Ticket.objects.get(id=id)
            if request.user.id == ticket.owner or request.user.has_perm("ticketcontrol.change_ticket"):
                if request.POST['title'] != "" and not None:
                    ticket.title = request.POST['title']
                if request.POST['location'] != "" and not None:
                    ticket.location = request.POST['location']
                if not request.POST['category'] in (0, "", "0", None):
                    ticket.category = Category.objects.get(id=request.POST['category'])
                ticket.save()
            else:
                return HttpResponse(status=403)
            return redirect("ticket_view", id=id)
        except ObjectDoesNotExist:
            return HttpResponse(status=404)
        except DatabaseError:
            return HttpResponse(status=409)

