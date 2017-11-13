from __future__ import unicode_literals
 
from django.db import models
 
import re
import bcrypt

class UserManager(models.Manager):
    def registration_validator(self, postData):
        errors = {}
        if len(postData['first_name']) < 2:
            errors['first_name'] = "First name must be at least 2 characters."
        if len(postData['last_name']) < 2:
            errors['last_name'] = "Last name must be at least 2 characters."
        EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
        if not EMAIL_REGEX.match(postData['email']):
            errors['email'] = "Email must be of valid email format."
        if len(postData['password']) < 8:
            errors['short_password'] = "Password must be 8 characters or more."
        if postData['password'] != postData['conf_password']:
            errors['password_mismatch'] = "Password and password confirmation must match."
        return errors

    def create_user(self, first, last, email, password):
        try:
            return User.objects.create(first_name=first, last_name=last, email=email, password=password)
        except:
            return None



    def login_validator(self, postData):
        errors = {}
        try:
            user = User.objects.get(email=postData['email'])
            if user:
                if bcrypt.checkpw(postData['password'].encode(), user.password.encode()):
                    return user
                else:
                    errors['pass_match'] = "Password does not match our records"
                return errors
        except:
            errors['not_reg'] = "You are not registered"
            return errors     



class User(models.Model): 
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()