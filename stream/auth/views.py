
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404

from django.contrib.auth import get_user_model
from rest_framework.generics import CreateAPIView, UpdateAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated

from .models import User

from random import randint
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response

from .serializers import EmailVerificationSerializer

User = get_user_model()





class EmailVerificationView(APIView):
    serializer_class = EmailVerificationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')
        otp = str(randint(100000, 999999))

        user = User.objects.filter(email=email).first()
        if user:
            user.otp = otp
            user.save()

            serializer.send_verification_email(email, otp)

        return Response({'message': 'Verification email has been sent.'}, status=status.HTTP_200_OK)


class VerifyOTPView(APIView):
    serializer_class = OtpVerificationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')
        otp = serializer.validated_data.get('otp')

        user = get_object_or_404(User, email=email, otp=otp)

        user.is_verified = True
        user.save()

        return Response({'message': 'Email has been verified.'}, status=status.HTTP_200_OK)


class UserRegistrationView(CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        status_code = status.HTTP_201_CREATED
        response = {
            'success': 'True',
            'status code': status_code,
            'message': 'User registered  successfully',
        }

        return Response(response, status=status_code)


class ChangePasswordView(UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = (IsAuthenticated,)

    def get_object(self, queryset=None):
        obj = self.request.user
        return obj

    def post(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get("old_password")):
                return Response({"old_password": ["Wrong password."]}, status=status.HTTP_400_BAD_REQUEST)
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()
            response = {
                'status': 'success',
                'code': status.HTTP_200_OK,
                'message': 'Password updated successfully',
                'data': []
            }

            return Response(response)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
