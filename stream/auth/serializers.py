from django.core.mail import send_mail, BadHeaderError
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

User = get_user_model()

class EmailVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def send_verification_email(self, email, otp):
        subject = 'OTP Verification'
        message = f'Your OTP verification code is {otp}'
        from_email = settings.EMAIL_HOST_USER
        to_email = email

        try:
            send_mail(subject, message, from_email, [to_email], fail_silently=False)
        except BadHeaderError:
            raise serializers.ValidationError('Invalid header found.')




class RegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )

    password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ('username', 'password', 'password2', 'email', 'first_name', 'last_name')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password": "Password fields didn't match."})

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )

        user.set_password(validated_data['password'])
        user.save()

        return user


class ResetVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def send_verification_email(self, email, otp_reset):
        subject = 'OTP Verification'
        message = f'Your OTP verification code is {otp_reset}'
        from_email = settings.EMAIL_HOST_USER
        to_email = email

        try:
            send_mail(subject, message, from_email, [to_email], fail_silently=False)
        except BadHeaderError:
            raise serializers.ValidationError('Invalid header found.')


class OtpResetSerializer(serializers.Serializer):
    otp_reset = serializers.CharField()
    email = serializers.EmailField()

    class Meta:
        model = User
        fields = ['otp_reset', 'email']