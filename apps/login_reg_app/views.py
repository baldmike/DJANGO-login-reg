from __future__ import unicode_literals
from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from time import strftime, localtime
from django.core.urlresolvers import reverse
 
from models import *

def index(request):
    if 'user_id' in request.session:
        return redirect('/dashboard')
    else:
        return render(request, 'login_reg_app/index.html')

def dashboard(request):
    if 'user_id' in request.session:
        return render(request, 'login_reg_app/dashboard.html')
    else:
        return render(request, 'login_reg_app/index.html')

def register(request):

    errors = User.objects.registration_validator(request.POST)
    if len(errors):
        for tag, error in errors.iteritems():
            messages.add_message(request, messages.ERROR, errors[tag])
        return redirect('login_reg_app:login')
    else:
        first_name =  request.POST['first_name']
        last_name = request.POST['last_name']
        email = request.POST['email']
        hashed_password = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
 
        user = User.objects.create_user(first_name, last_name, email, hashed_password)

        if not user:
            messages.add_message(request, messages.ERROR, "User email already exists.")
            return redirect('login_reg_app:login')
        else:
            request.session['user_id'] = user.id
            request.session['first_name'] = user.first_name
            request.session['last_name'] = user.last_name
            request.session['email'] = user.email
            return redirect('login_reg_app/dashboard.html')
        

def login(request):
    try:
        user = User.objects.login_validator(request.POST)

        if user:
            request.session['user_id'] = user.id
            request.session['first_name'] = user.first_name
            request.session['last_name'] = user.last_name
            request.session['email'] = user.email
            return redirect('/')
        else:
            messages.add_message(request, messages.ERROR, "Invalid login info.")
            return redirect("/")
    except:
        messages.add_message(request, messages.ERROR, "Not in database")
        return redirect('/')

def logout(request):
    request.session.flush()
    return redirect('/')