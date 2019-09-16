from django.shortcuts import render
from django.db.models import Q
from django.http import JsonResponse, HttpResponse, HttpRequest, HttpResponseBadRequest
import logging
import simplejson
from .models import User
from django.db.models.query import QuerySet
from django.conf import settings
import jwt
import datetime
import bcrypt
AUTH_EXPIRE = 60*60*8


FORMAT = "%(asctime)s %(threadName) %(thread)d %(message)s"
logging.basicConfig(format=FORMAT, level=logging.INFO)


def gen_token(user_id):
    '''
    token验证
    :param user_id:
    :return: base64编码
    '''
    ret = jwt.encode({"user_id": user_id,
                      "exp": int(datetime.datetime.now().timestamp()) + AUTH_EXPIRE},
                      settings.SECRET_KEY,
                      "HS256"
                      )
    return ret.decode() #返回需要字符串

def reg(request):
    try:
        payload = simplejson.loads(request.body.decode())
        email = payload['email']
        qs = User.objects.filter(email=email)
        if qs:
            return HttpResponseBadRequest()
        name = payload['name']
        password = payload['password']
        print(email, name, password)

        user = User()
        user.email = email
        user.name = name
        user.password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()) #加盐加密
        try:
            user.save()
            return JsonResponse({"token":gen_token(user.id)})
        except Exception as e:
            logging.info(e)
            return HttpResponseBadRequest()
    except Exception as e:
        logging.info(e)
        return HttpResponseBadRequest()


def login(request:HttpRequest):
    try:
        payload = simplejson.loads(request.body)
        email = payload['email']
        password = payload['password']
        user = User.objects.filter(email=email).first()
        if not user:
            return HttpResponseBadRequest()
        if not bcrypt.checkpw(password.encode(), user.password.encode()):
            return HttpResponseBadRequest()
        return JsonResponse({
            "user":{
                'user_id':user.id,
                'name': user.name,
                'email': user.email
            },"token": gen_token(user.id)
        })
    except Exception as e:
        print(e)
        return HttpResponseBadRequest()


#认证中心
def authenticate(view):
    #header request jwt
    def wrapper(request:HttpRequest):
        token = request.META.get("HTTP_JWT")
        # print(token, "+++++++++")
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            # if datetime.datetime.now().timestamp() - payload['timestamp'] > AUTH_EXPIRE:
            #     return HttpResponse(status=401)
            user_id = payload['user_id']
            user = User.objects.get(pk=user_id)
            request.user = user
        except Exception as e:
            print(e)
            return HttpResponse(status=401)
        return view(request)
    return wrapper


@authenticate
def test(request:HttpRequest):
    return HttpResponse(b"test")

