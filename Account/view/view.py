from django.shortcuts import render, redirect

from django.contrib.auth import get_user_model
User = get_user_model()

from django.views import generic
from django.contrib.auth.mixins import LoginRequiredMixin


class Login(generic.TemplateView):
    template_name = "account/Auth_Form/Login.html"


class Registrations(generic.TemplateView):
    template_name = "account/Auth_Form/Registrations.html"


class Home(generic.TemplateView):
    template_name = "home.html"


class Profiel(generic.TemplateView):
    template_name = "Profile/profile_info.html"


class Change_Password(generic.TemplateView):

    template_name = "Profile/change_password.html"



class takeEmail_forgetPass(generic.TemplateView):
    template_name = "ForgetPassword/take_email.html"



class varifyOTP_forgetPass(generic.TemplateView):
    template_name = "ForgetPassword/otp_varify.html"



class passwordSet_forgetPass(generic.TemplateView):
    template_name = "ForgetPassword/password_set.html"



