# Generated by Django 4.0.5 on 2022-06-12 14:48

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('ticketcontrol', '0018_remove_category_color'),
    ]

    operations = [
        migrations.RenameField(
            model_name='attachment',
            old_name='creationDate',
            new_name='creation_date',
        ),
        migrations.RenameField(
            model_name='comment',
            old_name='creationDate',
            new_name='creation_date',
        ),
        migrations.RenameField(
            model_name='ticket',
            old_name='creationDate',
            new_name='creation_date',
        ),
    ]
