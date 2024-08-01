from django.db import models
from django.contrib.auth.models import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser

class UserManager(BaseUserManager):

  # 식별자로 email, 속성으로 nickname 을 가지는 유저 모델 생성
  def create_user(self, email, nickname, password=None):
    if not email:
      raise ValueError('must have user email')
    user = self.model( email=email )
    user.nickname = nickname
    user.set_password(password)
    user.save()
    return user

  def create_superuser(self, email, nickname, password=None):
    if not email:
      raise ValueError('must have user email')
    user = self.model( email=email )
    user.nickname = nickname
    user.is_admin = True
    user.set_password(password)
    user.save()
    return user

class User(AbstractBaseUser):
  email = models.EmailField(unique=True)
  nickname = models.CharField(max_length=30, unique=True, null=False)
  is_active = models.BooleanField(default=True)
  is_admin = models.BooleanField(default=False)

  objects = UserManager()

  # unique identifier 설정
  USERNAME_FIELD = 'email'
  # 필수로 받고 싶은 값 - USERNAME_FIELD 값과 패스워드는 항상 기본으로 요구하므로 여기에 추가로 명시 필요 없음
  # 슈퍼유저를 생성할 때 적용 됨!
  REQUIRED_FIELDS = ['nickname']

  @property
  def is_staff(self):
    return self.is_admin