from rest_framework import serializers
from django.contrib.auth import authenticate

from .models import User


class RegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=128, min_length=8, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'username', 'password', 'token']

    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

class LoginSerializer(serializers.Serializer):
    email = serializers.CharField(max_length=255)
    username = serializers.CharField(max_length=255, read_only=True)
    password = serializers.CharField(max_length=128, write_only=True)
    token = serializers.CharField(max_length=255, read_only=True)

    def validate(self, data):
        email = data.get('email', None)
        password = data.get('password', None)
        if email is None:
            raise serializers.ValidationError('Адрес электронной почты необходим для входа в систему.')
        if password is None:
            raise serializers.ValidationError('Пароль необходим для входа в систему.')

        user = authenticate(username=email, password=password)
        if user is None:
            raise serializers.ValidationError('Пользователь с этим адресом электронной почты и паролем не найден.')
        if not user.is_active:
            raise serializers.ValidationError('Этот пользователь был деактивирован.')
        return {
            'email': user.email,
            'username': user.username,
            'token': user.token
        }

class UserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=128, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ('email', 'username', 'password', 'token',)
        read_only_fields = ('token',)

    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for key, value in validated_data.items():
            setattr(instance, key, value)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance