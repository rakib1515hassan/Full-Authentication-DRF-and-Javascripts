from django.db import models
from django.db.models.signals import post_save
from django.contrib.auth import get_user_model
# User = get_user_model()

import uuid
from django.contrib.auth.models import AbstractUser
from Account.manager import CustomUserManager



# Create your models here.
class User(AbstractUser):
    # NOTE যদি আমরা email এর সাহায্যে Login করতে চাই তাবে username = None এবং USERNAME_FIELD = 'email' দিতে হবে,
    username = None
    
    id = models.UUIDField( primary_key = True, unique=True, default = uuid.uuid4, editable=False )

    email = models.EmailField( unique= True )

    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = [] 

    objects = CustomUserManager()

    def __str__(self):
        return self.email






class UserInfo(models.Model):
    id = models.UUIDField( primary_key = True, unique=True, default = uuid.uuid4, editable=False )

    user        = models.OneToOneField( User, on_delete=models.CASCADE )
    
    phone       = models.CharField(max_length=20, null=True, blank=True)
    birth_date  = models.CharField(max_length=20, null=True, blank=True)
    profile_pic = models.ImageField(upload_to="ProfileImage/", null=True, blank=True)

    # signals_section
    # def create_profile(sender, **kwargs):
    #     user = kwargs["instance"]
    #     if kwargs["created"]:
    #         user_info = UserInfo(user=user)
    #         user_info.save()

    # post_save.connect(create_profile, sender=User)

    def __str__(self):
        return self.user.email





class User_OTP(models.Model):
    id = models.UUIDField( primary_key = True, default = uuid.uuid4, editable=False )

    user       = models.OneToOneField( User, on_delete=models.CASCADE )

    otp        = models.IntegerField()
    created_at = models.DateTimeField( auto_now_add=True )

    def __str__(self):
        return self.user.email
    



