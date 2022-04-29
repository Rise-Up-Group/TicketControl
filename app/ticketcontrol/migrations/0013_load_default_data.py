from django.db import migrations

def combine_names(apps, schema_editor):
    BasePermission = apps.get_model("auth", "Permission")
    Permission = apps.get_model("ticketcontrol", "Permission")
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

class Migration(migrations.Migration):

    dependencies = [
        ('ticketcontrol', '0012_permission'),
    ]

    operations = [
        migrations.RunPython(combine_names),
    ]