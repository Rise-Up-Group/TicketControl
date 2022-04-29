from django.contrib.auth.models import Permission as BasePermission, Group
from django.contrib.contenttypes.models import ContentType
from django.db import connection

from .models import Permission, User, Category


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
                "delete_ticket",
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
                "ticketcontrol": [
                    "view_ticket", "add_ticket", "change_ticket", "delete_ticket",
                    "view_comment", "add_comment", "change_comment", "delete_comment",
                    "view_attachment", "add_attachment", "change_attachment", "delete_attachment",
                    "view_group", "view_user", "view_category"
                ]
            },
            "user": {
                "ticketcontrol": [
                    "view_comment", "add_comment",
                    "view_ticket", "add_ticket",
                    "view_attachment", "view_category", "view_user"
                ]
            }
        }
        for group_name in default_groups:
            group = Group.objects.create(name=group_name)
            for app_label in default_groups[group_name]:
                contenttype = ContentType.objects.get(app_label=app_label)
                for permission in default_groups[group_name][app_label]:
                    perm = Permission.objects.get(contenttype=contenttype, codename=permission)
                    group.permissions.add(perm)


def load_admin_user():
    if User.objects.count() == 0:
        User.add_user("admin@example.com", "admin", "admin", "admin", "admin",
                      groups=[Group.objects.get(name="admin").id], is_active=True, is_superuser=True)


def load_categories():
    if Category.objects.count() == 0:
        Category.objects.create(name="Default", color="ffffffff")
        Category.objects.create(name="Other", color="5e5e5eff")
        Category.objects.create(name="IT-Support", color="0000ffff")


def load_initial_data():
    if "ticketcontrol_permission" in connection.introspection.table_names():
        load_permissions()
        if "auth_group" in connection.introspection.table_names():
            load_groups()
            if "ticketcontrol_user" in connection.introspection.table_names():
                load_admin_user()
    if "ticketcontrol_category" in connection.introspection.table_names():
        load_categories()
