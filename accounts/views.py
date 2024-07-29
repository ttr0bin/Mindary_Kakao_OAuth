import os
import requests
import jwt
from django.shortcuts import render
from rest_framework import status
from dotenv import load_dotenv
load_dotenv()

from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response

from rest_framework_simplejwt.tokens import RefreshToken

from accounts.models import User
from accounts.serializers import KakaoLoginRequestSerializer, KakaoRegisterRequestSerializer, UserSerializer


def exchange_kakao_access_token(access_code):
		# access_code : 프론트가 넘겨준 인가 코드
		
    token = requests.post(
        'https://kauth.kakao.com/oauth/token',
        headers={
            'Content-type': 'application/x-www-form-urlencoded;charset=utf-8',
        },
        data={
            'grant_type': 'authorization_code',
            'client_id': os.environ.get('KAKAO_REST_API_KEY'),
            'redirect_uri': os.environ.get('KAKAO_REDIRECT_URI'),
            'code': access_code,
        },
    )

		# 300번대 이상이면 다른 조치
    if token.status_code >= 300:
        return Response({'detail': 'Access token exchange failed'}, status=status.HTTP_401_UNAUTHORIZED)

    return token.json()

def extract_kakao_email(kakao_data):
		# 응답으로 받은 id_token 값 가져오기
    id_token = kakao_data.get('id_token', None)
    
    if id_token is None: # 없으면 예외 처리
        return Response({'detail': 'Missing ID token'}, status=status.HTTP_401_UNAUTHORIZED)
    
    # JWT 키 가져오기 - 서명 검증에 필요한 키
    jwks_client = jwt.PyJWKClient(os.environ.get('KAKAO_OIDC_URI'))
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    # JWT의 알고리즘 가져오기 (JWT 헤더에 포함된 정보) - 서명 검증에 필요
    signing_algol = jwt.get_unverified_header(id_token)['alg']

    try: # id_token=jwt의 페이로드에는 사용자 인증 정보들이 담겨 있음
        payload = jwt.decode( # JWT 디코딩 -> 페이로드 추출
            id_token,
            key=signing_key.key,               # JWT의 서명 검증
            algorithms=[signing_algol],        # |-> 유효한지 확인
            audience=os.environ.get('KAKAO_REST_API_KEY'),
        )
        return payload['email']
    except jwt.InvalidTokenError:
        return Response({'detail': 'OIDC auth failed'}, status=status.HTTP_401_UNAUTHORIZED)
    
@api_view(['POST'])
@permission_classes([AllowAny])
def kakao_login(request):
    serializer = KakaoLoginRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    data = serializer.validated_data
    
    # 인가 코드로 토큰 발급 -> 닉네임 추출
    kakao_data = exchange_kakao_access_token(data['access_code'])
    email = extract_kakao_email(kakao_data)
    print(email)

    try: # 해당 email을 가진 user가 있는지 확인
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({'detail': '존재하지 않는 사용자입니다.'}, status=404)

		# user login 처리

		# user 확인 했으므로 우리 토큰 발행
    refresh = RefreshToken.for_user(user)
    return Response({
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh)
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([AllowAny])
def kakao_register(request):
    serializer = KakaoRegisterRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    data = serializer.validated_data
    print(data)

    kakao_data = exchange_kakao_access_token(data['access_code'])
    email = extract_kakao_email(kakao_data)
    print(email)
    nickname = data.get('nickname')

    if not nickname:
        return Response({"error": "Nickname is required"}, status=status.HTTP_400_BAD_REQUEST)

	# 이미 존재하는 사용자 예외처리
    ok = False
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        ok = True
    if not ok:
        return Response({'detail': '이미 등록 된 사용자입니다.'}, status=400)

    # new 사용자 : 인증하고 우리의 토큰 발급
    user = User.objects.create_user(email=email, nickname=nickname)
    
    refresh = RefreshToken.for_user(user)
    return Response({
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh)
    }, status=status.HTTP_200_OK)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def kakao_logout(request): #토큰 만료 
    
    

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify(request):
    return Response({'datail': 'Token is verified.'}, status=200)