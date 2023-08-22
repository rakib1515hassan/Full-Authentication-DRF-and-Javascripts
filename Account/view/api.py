from django.contrib.auth import get_user_model
User = get_user_model()
from Account.models import UserInfo

from django.contrib.auth import authenticate

from Account.serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer, 
    UserChangePasswordSerializer, 
    SendPasswordResetEmailSerializer, 
    UserOTPverifySerializer,
    UserPasswordResetSerializer,

    UserInfoProfileSerializer,
)

from rest_framework.views import APIView
from rest_framework import generics

from rest_framework import status
from rest_framework.response import Response
from rest_framework.permissions import (
    IsAuthenticated, 
)

from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication


# NOTE ------------( Creating tokens manually )------------------------------------------

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


# NOTE ------------------( User Registration View )-------------------------------------
# URL = ( http://127.0.0.1:8000/auth/api/register/ )
class UserRegistrationView(APIView):

    def post(self, request, format=None):

        # print("-------------")
        # print(request.data)
        # print("-------------")

        user_serializer = UserRegistrationSerializer( data = request.data )

        if user_serializer.is_valid(raise_exception=True):
            user_serializer.save()

            return Response({'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)
        
        return Response(user_serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

# NOTE ------------------------( User Login View )----------------------------------------
# URL = ( http://127.0.0.1:8000/auth/api/login/ )
class UserLoginView(APIView):

    def post(self, request, format=None):
        
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')

            user = authenticate( email = email , password = password )            

            if user is not None:
                token = get_tokens_for_user(user)   ## Token Genaret
                return Response({'token': token,'msg':'Login Success'}, status=status.HTTP_200_OK)
            else:
                return Response({'errors':{'non_field_errors':['Username or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)
                        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    



    
#_________________________________________________________________________________________
# NOTE ------------------------( User Profile View )--------------------------------------
# URL = ( http://127.0.0.1:8000/auth/api/profile/ )

class UserProfileView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, format=None):
        user_info = UserInfo.objects.get(user=request.user)
        serializer = UserInfoProfileSerializer(user_info)
        return Response(serializer.data, status=status.HTTP_200_OK)
    

class UserProfileEditView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk, format=None):
        # print("-------------------------")
        # print("request data", request.data)
        # print("-------------------------")
        user_info = UserInfo.objects.get(user=request.user)
        serializer = UserInfoProfileSerializer(user_info, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"msg": "Profile is successfully updated."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#______________________________________________________________________________________



# NOTE ------------------------( ChangePasswor View )----------------------------------
# URL = ( http://127.0.0.1:8000/auth/api/change-password/ )
class UserChangePasswordView(APIView):

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        # print("-----------------")
        # print(request.data)
        # print("-----------------")
        serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password is successfully changed.'}, status=status.HTTP_200_OK)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

#______________________________________________________________________________________




# NOTE -----------------( Passord Reset Email Send With OTP View )----------------

# NOTE OTP send in Email
# URL = ( http://127.0.0.1:8000/auth/api/reset-password-email-send/ )
class SendPasswordResetEmailView(APIView):

    def post(self, request, format=None):
        # print("----------------")
        # print("Reset Password = ", request.data)
        # print("----------------")
        serializer = SendPasswordResetEmailSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        
        return Response({'msg':'Password Reset OTP send on your Email. Please check it.'}, status=status.HTTP_200_OK)
    


# NOTE OTP Verify
# URL = ( http://127.0.0.1:8000/auth/api/reset-password-otp-verify/ )
class UserOTPverify(APIView):

    def post(self, request, format=None):
        serializer = UserOTPverifySerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        e = request.data['email']
        user = User.objects.filter(email = e).first()
         
        if user is not None:
            token = get_tokens_for_user(user)   ## Token Genaret
            return Response({'token': token,'msg':'Now set your password.', 'r_otp':request.data['user_otp'],}, status=status.HTTP_200_OK)
        else:
            return Response({'errors':{'non_field_errors':['User not found.']}}, status=status.HTTP_404_NOT_FOUND)
                                
    



# NOTE OTP Verification
# URL = ( http://127.0.0.1:8000/auth/api/reset-password-set/ )
class UserPasswordResetView(APIView):
    authentication_classes = [JWTAuthentication]

    def post(self, request, format=None):        
        serializer = UserPasswordResetSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)
    
#______________________________________________________________________________________



