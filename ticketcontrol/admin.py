from django.contrib import admin

from .models import User, Category, Comment, Ticket, Attachment

admin.site.register(User)
admin.site.register(Category)
admin.site.register(Comment)
admin.site.register(Ticket)
admin.site.register(Attachment)