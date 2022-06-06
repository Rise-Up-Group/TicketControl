from django.contrib.auth.models import Group
from django.contrib.auth.models import Permission as BasePermission
from django.contrib.auth.models import User as BaseUser
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from six import text_type
from django.db import models
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.core.mail import send_mail
import os

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
                text_type(user.reset_password) + text_type(user.password)
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

    def add_user(email, firstname, lastname, username, password, groups, is_active, email_confirmed=False,
                 is_superuser=None):
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
        if is_superuser is not None:
            user.is_superuser = is_superuser
        user.save()
        return user

    def update_user(self, email=None, first_name=None, last_name=None, username=None, password=None, groups=None,
                    is_active=None, email_confirmed=None):
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

    def send_emailverification_mail(self, request, new_user=True):
        message = render_to_string("email/activate_mail.html", {
            'user': self,
            'domain': get_current_site(request).domain,
            'token': account_activation_token.make_token(self),
        })
        if new_user:
            subject = "Welcome to Ticketcontrol"
        else:
            subject = "[Ticketcontrol] Confirm your EMail address"
        send_mail(
            subject=subject,
            message="",
            html_message=message,
            from_email=EMAIL_HOST_USER,
            recipient_list=[self.new_email],
            fail_silently=False
        )

    def send_passwordreset_mail(self, request):
        message = render_to_string("email/passwordreset_mail.html", {
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
    def delete(self):
        ghost = User.objects.get(username="ghost")
        tickets = self.ticket_set.all()
        for ticket in tickets:
            ticket.owner = ghost
            ticket.save()
        mod_tickets = Ticket.objects.filter(moderator=self.id)
        for ticket in mod_tickets:
            for mod in ticket.moderators.all():
                if mod.id == self.id:
                    ticket.moderators.remove(mod)
                    ticket.save()
        comments = self.comment_set.all()
        for comment in comments:
            comment.user = ghost
            comment.save()
        attachments = self.attachment_set.all()
        for attachment in attachments:
            attachment.user = ghost
            attachment.save()
        super().delete()

class Permission(models.Model):
    perm = models.OneToOneField(BasePermission, on_delete=models.DO_NOTHING)

    def __str__(self):
        return self.perm.name


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
    class Meta:
        permissions = (
            ("hide_ticket", "Hide the Ticket to everyone (shown as delete in the ui)"),
            ("unhide_ticket", "Recover the Ticket (shown as recover ticket in the ui)"),
            ("change_ticket_status", "Change Ticket status"),
            ("assign_ticket", "Assign Ticket to users"),
        )
    class StatusChoices(models.TextChoices):
        UNASSIGNED = 'Unassigned'
        ASSIGNED = 'Assigned'
        CLOSED = 'Closed'
        OPEN = 'Open'
        WAITING = 'Waiting'

    def add_ticket(title, description, owner, category, location):
        ticket = Ticket(title=title, description=description, owner=owner, category=category, status='Unassigned', location=location)
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

    def set_status(self, status):
        self.status = status
        self.save()

    def set_hidden(self, hidden):
        self.hidden = hidden
        self.save()

    def delete(self):
        comments = Comment.objects.filter(ticket=self.id)
        for comment in comments:
            attachments = Attachment.objects.filter(comment=comment.id)
            for attachment in attachments:
                os.remove("uploads/" + str(attachment.id))
                attachment.delete()
            comment.delete()

        attachments = Attachment.objects.filter(ticket=self.id)
        for attachment in attachments:
            os.remove("uploads/" + str(attachment.id))
            attachment.delete()

        super().delete()

    status = models.CharField(max_length=15, choices=StatusChoices.choices, default=StatusChoices.UNASSIGNED)
    creationDate = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.DO_NOTHING, related_name="owner")
    category = models.ForeignKey(Category, on_delete=models.DO_NOTHING)
    participating = models.ManyToManyField("User", blank=True)  # does NOT contain owner
    moderators = models.ManyToManyField("User", related_name="moderators", blank=True)
    hidden = models.BooleanField(default=False)
    location = models.CharField(max_length=255, null=True, blank=True)

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
        return self.filename + " (size: " + str(self.size) + ")"
