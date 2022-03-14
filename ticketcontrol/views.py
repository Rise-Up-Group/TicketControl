from django.http import HttpResponse
import datetime

from django.shortcuts import render
from .models import User, Ticket, Comment, Category

def mytickets_view(request):
    context = {}
    context["dataset"] = Ticket.objects.all()
    return render(request, "ticket/manage.html", context)
