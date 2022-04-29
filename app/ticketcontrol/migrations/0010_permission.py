# Generated by Django 4.0.4 on 2022-04-29 10:16

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('ticketcontrol', '0009_delete_permission'),
    ]

    operations = [
        migrations.CreateModel(
            name='Permission',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('perm', models.OneToOneField(on_delete=django.db.models.deletion.DO_NOTHING, to='auth.permission')),
            ],
        ),
    ]