from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.contrib.auth import authenticate 
from django.db.models import Q


from Account.models import UserInfo, User_OTP
from datetime import datetime, timedelta

# Sending Mail
from django.core.mail import send_mail
from django.conf import settings

from rest_framework.validators import UniqueValidator
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.password_validation import validate_password

User = get_user_model()



# NOTE ----------------------------------( Registration Serialize )------------------------------------
class UserInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserInfo
        fields = ['phone', 'birth_date']  



class UserRegistrationSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
            required=True,
            validators=[UniqueValidator(queryset=User.objects.all())]
            )

    password     = serializers.CharField(write_only=True, required=True, validators=[validate_password], style={'input_type':'password'})
    password2    = serializers.CharField(write_only=True, required=True, style={'input_type':'password'})

    user_info = UserInfoSerializer()

    class Meta:
        model = User
        fields = ( 'first_name', 'last_name', 'email', 'password', 'password2', 'user_info')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True},
            'password':{'write_only':True}
        }
    # Validating Password and Confirm Password while Registration
    def validate(self, attrs): # attrs means data
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})
        
        return attrs


    def create(self, validated_data):

        user_info_data = validated_data.pop('user_info')
        password2 = validated_data.pop('password2')

        user = User.objects.create(
            email      = validated_data['email'],
            first_name = validated_data['first_name'],
            last_name  = validated_data['last_name']
        )
        user.set_password(validated_data['password'])
        user.save()

        # user = User(**validated_data)
        # user.set_password('password')
        # user.save()

        user_info = UserInfo.objects.create(user=user, **user_info_data)

        return user_info
    
#______________________________________________________________________________________________________    


# NOTE --------------------------------------( Login Serialize )--------------------------------------

class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField( max_length = 250)
    class Meta:
        model = User
        fields = ['email', 'password']

#_____________________________________________________________________________________________________


# NOTE ------------------------------------( Profile Serialize )--------------------------------------
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        # fields = ['id', 'username', 'first_name', 'last_name', 'email']
        fields = ['id', 'first_name', 'last_name', 'email']


class UserInfoProfileSerializer(serializers.ModelSerializer):
    user = UserProfileSerializer()  

    # def validate_user(self, value):
    #     # Check if the new username is unique
    #     if 'username' in value and User.objects.filter(username=value['username']).exclude(pk=value['id']).exists():
    #         raise serializers.ValidationError("A user with that username already exists.")
    #     return value

    class Meta:
        model = UserInfo
        fields = ['id', 'phone', 'birth_date', 'profile_pic', 'user']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', None)
        if user_data:
            user = instance.user

            user.id         = user_data.get('id', user.id)
            # user.username   = user_data.get('username', user.username)
            user.first_name = user_data.get('first_name', user.first_name)
            user.last_name  = user_data.get('last_name', user.last_name)
            user.email      = user_data.get('email', user.email)

            user.save()

        instance.phone = validated_data.get('phone', instance.phone)
        instance.birth_date = validated_data.get('birth_date', instance.birth_date)
        instance.profile_pic = validated_data.get('profile_pic', instance.profile_pic)
        
        instance.save()
        return instance


#_____________________________________________________________________________________________________



# NOTE --------------------------------( ChangePasswor Serialize )------------------------------------
class UserChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)

    class Meta:
        fields = ['old_password', 'password', 'password2']

    def validate(self, attrs):
        old_password = attrs.get('old_password')
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user') # যেই user আমরা view.py function এর context এর মাধ্যমে send করেছি তা receive করা হয়েছে

        # Authenticate the user with the old password
        # if not authenticate(username=user.username, password=old_password):
        if not authenticate(email=user.email, password=old_password):
            raise serializers.ValidationError("Old password is incorrect")

        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password don't match")

        # Set the new password and save the user
        user.set_password(password)
        user.save()
        return attrs
#_____________________________________________________________________________________________________


# NOTE -----------------------------( Reset Passwor Email Send Serialize )---------------------------------

# For OTP
import random

class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email = email)

            # Django সেশনে email স্টোর করুন
            self.context['request'].session['email'] = email


            # NOTE If You send OTP on your email-------------------------------------
            otp = random.randint(100000, 999999)

            #Django সেশনে টাইমআউট সেট করাহয়েছে
            timeout_datetime = datetime.now() + timedelta( minutes = 3 )
            self.context['request'].session['timeout'] = timeout_datetime.timestamp()
       
            if User_OTP.objects.filter(user = user).exists(): # পুরাতন otp থাকলে তাকে এখনে delete করে দিবে
                User_OTP.objects.get(user = user).delete()

            otp_obj = User_OTP.objects.create(user = user, otp=otp)
            # print("Your OTP = ", otp)
            # print("Your Object = ", otp_obj)

            body = f"Hello {user.first_name}{user.last_name},\nYour OTP is {otp}\nThanks!"
            #-------------------------------------------------------------------------

            ## Send EMail-------------------------------------------------------------
            send_mail(
                "Reset Your Password",     # Subject
                body,                      # Body
                settings.EMAIL_HOST_USER,  # From
                [user.email],              # To
                fail_silently = False
            )
            #_________________________________________________________________________
            return attrs
        else:
            raise serializers.ValidationError('You are not a Registered User')
#_____________________________________________________________________________________________________


# NOTE -----------------------------( Reset Passwor OTP Verify )---------------------------------
class UserOTPverifySerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    user_otp = serializers.IntegerField()

    class Meta:
        fields = ['email', 'user_otp']

    def validate(self, attrs):
        email = attrs.get('email')
        user_otp = attrs.get('user_otp')

        timeout_timestamp = self.context['request'].session.get('timeout')

        # OTP submition টাইম 3 মিনিট এর বেসি হলে তা Error দিবে।
        timeout_datetime = datetime.fromtimestamp(timeout_timestamp)
        if datetime.now() > timeout_datetime:
            raise serializers.ValidationError("OTP verification time has expired")

        if User.objects.filter(email=email).exists():
            user = User.objects.get(email = email)

            if User_OTP.objects.filter(Q(user__email = email) & Q(otp = user_otp)).exists():
                return attrs
            
            raise serializers.ValidationError("Your OTP doesn't match")
        
        raise serializers.ValidationError("Your OTP doesn't match")
#_____________________________________________________________________________________________________


# NOTE -----------------------------( Reset Passwor Email Verify Serialize )---------------------------------

# NOTE IF OTP Verification-----------------------

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type':'password'}, write_only=True)
    otp = serializers.IntegerField()
    class Meta:
        fields = ['password', 'password2', 'otp']

    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        otp = attrs.get('otp')
        
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        
        # যেই email and OTP_timeout আমরা serializers.py  এর SendPasswordResetEmailSerializer class থেকে Django session এর মাধ্যমে 
        # send করেছি তা receive করা হয়েছে email এবং timeout_timestamp veriable এর ভেতর।
        email = self.context['request'].session.get('email')
        # timeout_timestamp = self.context['request'].session.get('timeout')

        # timeout_datetime = datetime.fromtimestamp(timeout_timestamp)
        # if datetime.now() > timeout_datetime:
        #     raise serializers.ValidationError("OTP verification time has expired")

        user_obj = User.objects.get(email = email) 

        otp_obj = User_OTP.objects.get(user = User.objects.get(email=email))

        
        if otp != otp_obj.otp:
            raise serializers.ValidationError("Your OTP doesn't match")

        user_obj.set_password(password)
        user_obj.save()
        return attrs
    
#_____________________________________________________________________________________________________


