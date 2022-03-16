from django.db import models

import datetime
from django.utils import timezone
from django.contrib.auth.models import User as BaseUser


class User(BaseUser):
    class RoleChoices(models.TextChoices):
        USER = 'usr'
        MOD = 'mod'
        ADMIN = 'adm'


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

    def __str__(self):
        return self.ticket.title + " Comment " + self.num


class Ticket(models.Model):
    class StatusChoices(models.TextChoices):
        UNASSIGNED = 'uas'
        ASSIGNED = 'ass'
        CLOSED = 'clo'
        OPEN = 'opn'
        WAITING = 'wat'

    status = models.CharField(max_length=3, choices=StatusChoices.choices, default=StatusChoices.UNASSIGNED)
    creationDate = models.DateTimeField(auto_now_add=True)
    title = models.CharField(max_length=255)
    description = models.TextField()
    owner = models.ForeignKey(User, on_delete=models.DO_NOTHING, related_name="owner")
    category = models.ForeignKey(Category, on_delete=models.DO_NOTHING)
    participating = models.ManyToManyField("User", blank=True)  # does NOT contain owner
    moderator = models.ManyToManyField("User", related_name="moderator", blank=True)#TODO: 'moderatorS'

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
