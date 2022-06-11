# Generated by Django 4.0.4 on 2022-06-06 20:09

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('ticketcontrol', '0015_alter_ticket_options'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='ticket',
            name='moderator',
        ),
        migrations.AddField(
            model_name='ticket',
            name='moderators',
            field=models.ManyToManyField(blank=True, related_name='moderators', to='ticketcontrol.user'),
        ),
    ]