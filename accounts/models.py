from django.db import models

class UserProfile(models.Model):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField()
    first_name = models.CharField(max_length=100, blank=True)
    last_name = models.CharField(max_length=100, blank=True)

class UserToken(models.Model):
    user = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    custom_token = models.CharField(max_length=100)
