import jwt
from fastapi import HTTPException
from passlib.context import CryptContext
from datetime import datetime,timedelta
from decouple import config
from typing import Tuple

JWT_KEY=config('JWT_KEY')

class AuthJwtCsrf():
    pwd_ctx=CryptContext(schemes=["bcrypt"],deprecated="auto")
    secret_key=JWT_KEY

    def generate_hashed_pw(self,password) -> str:#入力されたパスワードを受け入れて
        return self.pwd_ctx.hash(password)#ハッシュ化して返す
    
    def verify_pw(self,plain_pw,hashed_pw)->bool:#パスワードと入力されたパスワードを比較
        return self.pwd_ctx.verify(plain_pw,hashed_pw)#一致したら返す
    
    def encode_jwt(self,email)->str:#Eメールを受け取る
        payload={
            'exp':datetime.utcnow() + timedelta(days=0,minutes=5),#０日５分の有効期限
            'iat':datetime.utcnow(),
            'sub':email#Eメールを格納
        }
        return jwt.encode(#↑のpayload、シークレットキー、アルゴリズムでJWTを生成
            payload,
            self.secret_key,
            algorithm='HS256'
        )
    
    def decode_jwt(self,token)-> str:#JWTトークンを受け取りデコードする
        try:
            payload=jwt.decode(token,self.secret_key,algorithms=['HS256'])
            return payload['sub']
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401,detail='The JWT has expired')
        except jwt.InvalidTokenError as e:
            raise HTTPException(status_code=401,detail='JWT is not valid')    
            
    def verify_jwt(self,reqest)->str:#JWTトークンの検証
        token=reqest.cookies.get("access_token")#cookieからトークンを読み取る
        if not token:
            raise HTTPException(
                status_code=401,detail='No JWT exist: may not set yet or deleted')
        _, _, value=token.partition(" ")
        subject=self.decode_jwt(value)#上のdecode_jwtを起動してsubjextに
        return subject
    
    def verify_update_jwt(self,request)->Tuple[str,str]:#検証と更新をしてくれる
        subject=self.verify_jwt(request)
        new_token=self.encode_jwt(subject)
        return new_token,subject
    
    def verify_csrf_update_jwt(self,request,csrf_protect,headers)->str:#CSRF,tokenの検証、更新を行う
        csrf_token=csrf_protect.get_csrf_from_headers(headers)
        csrf_protect.validate_csrf(csrf_token)
        subject=self.verify_jwt(request)
        new_token=self.encode_jwt(subject)
        return new_token


