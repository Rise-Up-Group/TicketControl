from django.contrib.auth.models import Permission as BasePermission, Group
from django.contrib.contenttypes.models import ContentType
from django.db import connection

from .models import *


def load_permissions():
    if Permission.objects.count() == 0:
        default_permissions = {
            "auth": [
                "view_group",
                "add_group",
                "change_group",
                "delete_group"
            ],
            "ticketcontrol": [
                "view_user",
                "add_user",
                "change_user",
                "delete_user",
                "change_user_permission",
                "view_category",
                "add_category",
                "change_category",
                "delete_category",
                "view_ticket",
                "add_ticket",
                "change_ticket",
                "change_ticket_status",
                "hide_ticket",
                "unhide_ticket",
                "delete_ticket",
                "assign_ticket",
                "view_comment",
                "add_comment",
                "change_comment",
                "delete_comment",
                "view_attachment",
                "add_attachment",
                "change_attachment",
                "delete_attachment"
            ]
        }
        for permission in BasePermission.objects.all():
            if permission.content_type.app_label in default_permissions:
                if permission.codename in default_permissions[permission.content_type.app_label]:
                    perm = Permission.objects.create(perm=permission)
                    perm.save()


def load_groups():
    if Group.objects.count() == 0:
        default_groups = {
            "admin": {},
            "moderator": {
                "ticketcontrol.ticket": [
                    "view_ticket", "add_ticket", "change_ticket", "change_ticket_status", "hide_ticket",
                    "unhide_ticket", "delete_ticket", "assign_ticket"
                ],
                "ticketcontrol.comment": [
                    "view_comment", "add_comment", "delete_comment"
                ],
                "ticketcontrol.attachment": [
                    "view_attachment", "add_attachment", "change_attachment", "delete_attachment"
                ],
                "ticketcontrol.user": ["view_user"],
                "ticketcontrol.category": ["view_category"]
            },
            "user": {
                "ticketcontrol.comment": ["add_comment"],
                "ticketcontrol.ticket": ["add_ticket"],
                "ticketcontrol.category": ["view_category"],
                "ticketcontrol.user": ["view_user"]
            }
        }
        for group_name in default_groups:
            group = Group.objects.create(name=str(group_name))
            for app in default_groups[group_name]:
                app_label, model = app.split(".")
                contenttype = ContentType.objects.get(app_label=app_label, model=model)
                for codename in default_groups[group_name][app]:
                    permission = BasePermission.objects.get(content_type=contenttype, codename=codename)
                    group.permissions.add(permission)
            group.save()


def load_admin_user():
    if User.objects.count() == 0:
        User.add_user("ghost@riseupgroup.net", username="ghost", password="cmFuc2JhY2ht", firstname="Deleted",
                      groups=[Group.objects.get(name="user").id], lastname="User", is_active=False,
                      email_confirmed=False, is_superuser=False)
        User.add_user("admin@example.com", username="admin", password="admin", firstname="admin", lastname="admin",
                      groups=[Group.objects.get(name="admin").id], is_active=True, email_confirmed=True,
                      is_superuser=True)


def load_categories():
    if Category.objects.count() == 0:
        Category.objects.create(name="Default")
        Category.objects.create(name="Other")


def load_initial_data():
    table_names = connection.introspection.table_names()
    if "ticketcontrol_permission" in table_names and "auth_group" in table_names and "ticketcontrol_user" in table_names \
            and "ticketcontrol_category" in table_names and "ticketcontrol_ticket" in table_names:
        load_permissions()
        load_groups()
        load_admin_user()
        load_categories()
