from django.contrib import admin
from Account.models import User,UserInfo, User_OTP


# Register your models here.
admin.site.register(User)

@admin.register(UserInfo)
class UserInfo_admin(admin.ModelAdmin):
    list_display = ( 'id', 'Email', 'phone', 'birth_date', 'profile_pic')

    def Email(self, obj):
        return obj.user.email
    


@admin.register(User_OTP)
class User_OTP_admin(admin.ModelAdmin):
    list_display = ( 'id','Email', 'otp', 'created_at')

    def Email(self, obj):
        return obj.user.email
    
    Email.short_description = 'Email'





