from django.urls import path
from Account.view import api
from Account.view import view

urlpatterns = [

    ## NOTE Tamplate Render URL:-
    path("home/", view.Home.as_view(), name='home'),
    path("profile/", view.Profiel.as_view(), name='profile'),
    path("change-password/", view.Change_Password.as_view(), name='change_password'),
    path("take-mail/", view.takeEmail_forgetPass.as_view(), name='takeEmail_f_password'),
    path("varify-otp/", view.varifyOTP_forgetPass.as_view(), name='varifyOTP_f_password'),
    path("password-set/", view.passwordSet_forgetPass.as_view(), name='passwordSet_forgetPass'),




    ## NOTE API Endpoints:-
    path('api/register/', api.UserRegistrationView.as_view(), name='UserRegistrationView'),
    path('api/login/', api.UserLoginView.as_view(), name='UserLoginView'),

    ## Profile
    path('api/profile/', api.UserProfileView.as_view(), name='UserProfileView'),
    path('api/profile/<uuid:pk>/', api.UserProfileEditView.as_view(), name='update_user_profile'),
    
    ## Change Password
    path('api/change-password/', api.UserChangePasswordView.as_view(), name='UserChangePasswordView'),

    ## Forget Password
    path('api/reset-password-email-send/', api.SendPasswordResetEmailView.as_view(), name='SendPasswordResetEmailView'),
    path('api/reset-password-otp-verify/', api.UserOTPverify.as_view(), name='UserOTPverify'),
    path('api/reset-password-set/', api.UserPasswordResetView.as_view(), name='UserPasswordResetSerializer'),

]

