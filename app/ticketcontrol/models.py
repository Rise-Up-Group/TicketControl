from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission as BasePermission
from django.contrib.auth.models import User as BaseUser
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type
from django.db import models
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import send_mail

from .settings import EMAIL_HOST_USER


class AccountActivationToken(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            text_type(user.pk) + text_type(timestamp) +
            text_type(user.email_confirmed) + text_type(user.email)
        )


class PasswordResetToken(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (
            text_type(user.pk) + text_type(timestamp) +
            text_type(user.reset_password)
        )


account_activation_token = AccountActivationToken()
password_reset_token = PasswordResetToken()

class User(BaseUser):
    class Meta:
        permissions = (
            ("change_user_permission", "Change the permissions of other users"),
            ("admin_general", "Allow access to the Admin Panel"),
        )

    new_email = models.EmailField(blank=True)
    email_confirmed = models.BooleanField(default=False)
    reset_password = models.BooleanField(default=False)

    def add_user(email, firstname, lastname, username, password, groups, is_active, email_confirmed=False):
        # TODO: preview in javascrip and show to user
        # TODO: nickname has to be unique (possibly with db)
        if username == "":
            username = firstname[0:1] + ". " + lastname
        # Creates ticketcontrol.user; never create a BaseUser
        user = User.objects.create_user(username=username, password=password, email=email)
        user.first_name = firstname
        user.last_name = lastname
        if groups is not None:
            for group in groups:
                Group.objects.get(id=group).user_set.add(user)
            user.is_superuser = False
            user.is_staff = False
            adminId = Group.objects.get(name="Admin").id
            for groupId in groups:
                if int(groupId) == adminId:
                    user.is_superuser = True
                    user.is_staff = True
        else:
            Group.objects.get(name="user").user_set.add(user)
        user.is_active = is_active
        user.email_confirmed = email_confirmed
        user.save()
        return user

    def update_user(self, email=None, first_name=None, last_name=None, username=None, password=None, groups=None, is_active=None, email_confirmed=None):
        if email is not None and self.email != email:
            self.new_email = email
        if first_name is not None:
            self.first_name = first_name
        if last_name is not None:
            self.last_name = last_name
        if username is not None:
            self.username = username
        if password != "" and password is not None:
            self.set_password(password)

        if groups is not None:
            userGroups = self.groups.all()
            for group in userGroups:
                if not group.id in groups:
                    Group.objects.get(id=group.id).user_set.remove(self)
            for group in groups:
                found = False
                for userGroup in userGroups:
                    if userGroup.id == group:
                        found = True
                if not found:
                    Group.objects.get(id=group).user_set.add(self)

            self.is_superuser = False
            self.is_staff = False
            adminId = Group.objects.get(name="admin").id
            for groupId in groups:
                if int(groupId) == adminId:
                    self.is_superuser = True
                    self.is_staff = True

        if is_active is not None:
            self.is_active = is_active
        if email_confirmed is not None:
            self.email_confirmed = email_confirmed
        self.save()

    def delete_user(id):
        User.objects.get(id=id).delete()

    def send_emailverification_mail(self, request, new_user=True):
        message = render_to_string("user/activate_mail.html", {
            'user': self,
            'domain': get_current_site(request).domain,
            'token': account_activation_token.make_token(self),
        })
        if new_user:
            subject = "Welcome to Ticketcontrol"
        else:
            subject="[Ticketcontrol] Confirm your EMail address"
        send_mail(
            subject=subject,
            message="",
            html_message=message,
            from_email=EMAIL_HOST_USER,
            recipient_list=[self.email],
            fail_silently=False
        )

    def send_passwordreset_mail(self, request):
        message = render_to_string("user/passwordreset_mail.html", {
            'user': self,
            'domain': get_current_site(request).domain,
            'token': password_reset_token.make_token(self),
        })
        send_mail(
            subject="[Ticketcontrol] Reset your password",
            message="",
            html_message=message,
            from_email=EMAIL_HOST_USER,
            recipient_list=[self.email],
            fail_silently=False
        )


class Permission(BasePermission):
    def __str__(self):
        return self.name


class Category(models.Model):
    name = models.CharField(max_length=256)
    color = models.CharField(max_length=8)

    def __str__(self):
        return self.name


class Comment(models.Model):
    content = models.TextField()
    creationDate = models.DateTimeField(auto_now_add=True)
    num = models.IntegerField()
    ticket = models.ForeignKey("Ticket", on_delete=models.DO_NOTHING)
    user = models.ForeignKey("User", on_delete=models.DO_NOTHING)

    def __str__(self):
        return self.ticket.title + " Comment " + str(self.num)


class Ticket(models.Model):
    class StatusChoices(models.TextChoices):
        UNASSIGNED = 'Unassigned'
        ASSIGNED = 'Assigned'
        CLOSED = 'Closed'
        OPEN = 'Open'
        WAITING = 'Waiting'

    def add_ticket(title, description, owner, category):
        ticket = Ticket(title=title, description=description, owner=owner, category=category, status='Unassigned')
        ticket.save()
        return ticket

    def add_comment(self, content, user):
        comment = Comment(content=content, ticket=self, user=user)
        try:
            comment.num = Comment.objects.get(ticket=self).count() + 1,
        except:
            comment.num = 1

        comment.save()
        return comment

    status = models.CharField(max_length=15, choices=StatusChoices.choices, default=StatusChoices.UNASSIGNED)
    creationDate = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.DO_NOTHING, related_name="owner")
    category = models.ForeignKey(Category, on_delete=models.DO_NOTHING)
    participating = models.ManyToManyField("User", blank=True)  # does NOT contain owner
    moderator = models.ManyToManyField("User", related_name="moderator", blank=True)  # TODO: 'moderatorS'

    def __str__(self):
        return self.title + " (" + self.owner.username + ")"


class Attachment(models.Model):
    filename = models.CharField(max_length=255)
    size = models.IntegerField()
    creationDate = models.DateTimeField(auto_now_add=True)
    ticket = models.ForeignKey(Ticket, on_delete=models.DO_NOTHING, null=True, blank=True)
    comment = models.ForeignKey(Comment, on_delete=models.DO_NOTHING, null=True, blank=True)
    user = models.ForeignKey(User, on_delete=models.DO_NOTHING, null=False, blank=False)

    def __str__(self):
        return self.ticket.title + " File: " + self.filename + "(" + self.size + ")"
