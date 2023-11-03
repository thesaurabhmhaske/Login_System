import json
import pymongo
import firebase_admin
from firebase_admin import auth
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.decorators import api_view
from rest_framework import status
from django.contrib.auth.hashers import make_password, check_password
from django.db.utils import IntegrityError
from .models import UserProfile, UserToken
from .serializers import UserProfileSerializer

# MongoDB Configuration
MONGODB_HOST = 'mhaskesaurabh024'
MONGODB_PORT = 27017
MONGODB_DB_NAME = 'LoginSys'

def get_mongodb_collection(collection_name):
    client = pymongo.MongoClient(host=MONGODB_HOST, port=MONGODB_PORT)
    db = client[MONGODB_DB_NAME]
    return db[collection_name]

@csrf_exempt
@api_view(['POST'])
def register(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        first_name = data.get('first_name', '')
        last_name = data.get('last_name', '')

        if not (username and email and password):
            return JsonResponse(
                {'error': 'Email and password are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        if len(password) < 8:
            return JsonResponse(
                {'error': 'This password is too short. It must contain at least 8 characters.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            user_collection = get_mongodb_collection('user_profiles')
            existing_user = user_collection.find_one({'username': username})

            if existing_user:
                return JsonResponse(
                    {'error': 'A user with that username already exists.'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            user_data = {
                'username': username,
                'email': email,
                'first_name': first_name,
                'last_name': last_name,
                'password': make_password(password),
            }
            user_collection.insert_one(user_data)

            user = UserProfile(username=username, email=email, first_name=first_name, last_name=last_name)
            custom_token = auth.create_custom_token(user.id)

            user_token, _ = UserToken.objects.get_or_create(user=user)
            user_token.custom_token = custom_token
            user_token.save()

            return JsonResponse(
                {'username': user_data['username'], 'email': user_data['email'], 'custom_token': custom_token},
                status=status.HTTP_201_CREATED
            )

        except IntegrityError:
            return JsonResponse(
                {'error': 'Email must be unique.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        

@csrf_exempt
@api_view(['POST'])
def login(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        username = data.get('username')
        password = data.get('password')

        try:
            user_collection = get_mongodb_collection('user_profiles')
            user_data = user_collection.find_one({'username': username})

            if not user_data:
                return JsonResponse(
                    {'error': 'Username or password is invalid.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            if not check_password(password, user_data['password']):
                return JsonResponse(
                    {'error': 'Username or password is invalid.'},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            user = UserProfile(username=username, email=user_data['email'])
            custom_token = auth.create_custom_token(user.id)

            user_token, _ = UserToken.objects.get_or_create(user=user)
            user_token.custom_token = custom_token
            user_token.save()

            return JsonResponse(
                {
                    'username': user_data['username'],
                    'email': user_data['email'],
                    'full_name': f"{user_data['first_name']}-{user_data['last_name']}",
                    'custom_token': custom_token,
                },
                status=status.HTTP_200_OK
            )

        except Exception as e:
            return JsonResponse(
                {'error': 'An error occurred during login.'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


@api_view(['GET', 'POST'])
def view_profile(request):
    custom_token = request.META.get('HTTP_CUSTOM_TOKEN')

    try:
        decoded_token = auth.verify_custom_token(custom_token)
        user_id = decoded_token['uid']
    except auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid custom token'}, status=status.HTTP_401_UNAUTHORIZED)

    user_collection = get_mongodb_collection('user_profiles')
    user_data = user_collection.find_one({'_id': user_id})

    if not user_data:
        return JsonResponse({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    serializer = UserProfileSerializer(user_data)
    return JsonResponse(serializer.data, status=status.HTTP_200_OK)

@api_view(['POST'])
def edit_profile(request):
    custom_token = request.META.get('HTTP_CUSTOM_TOKEN')

    try:
        decoded_token = auth.verify_custom_token(custom_token)
        user_id = decoded_token['uid']
    except auth.InvalidIdTokenError:
        return JsonResponse({'error': 'Invalid custom token'}, status=status.HTTP_401_UNAUTHORIZED)

    user_collection = get_mongodb_collection('user_profiles')
    user_data = user_collection.find_one({'_id': user_id})

    if not user_data:
        return JsonResponse({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)

    data = json.loads(request.body)
    new_username = data.get('username', user_data['username'])

    if new_username != user_data['username'] and user_collection.find_one({'username': new_username}):
        return JsonResponse(
            {'error': f'User already exists with the username {new_username}.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    user_collection.update_one(
        {'_id': user_id},
        {
            '$set': {
                'username': new_username,
                'first_name': data.get('first_name', user_data['first_name']),
                'last_name': data.get('last_name', user_data['last_name']),
            }
        }
    )

    updated_user_data = user_collection.find_one({'_id': user_id})
    serializer = UserProfileSerializer(updated_user_data)
    return JsonResponse(serializer.data, status=status.HTTP_200_OK)
