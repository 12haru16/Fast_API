from decouple import config
from fastapi import HTTPException
from typing import Union
import motor.motor_asyncio
from bson import ObjectId
from auth_utils import AuthJwtCsrf
import asyncio

MONGO_API_KEY = config('MONGO_API_KEY')

client = motor.motor_asyncio.AsyncIOMotorClient(MONGO_API_KEY)
client.get_io_loop=asyncio.get_event_loop

database = client.API_DB
collection_todo = database.todo
collection_user = database.user
auth=AuthJwtCsrf()

def todo_serializer(todo) -> dict:
    return {
        "id": str(todo["_id"]),
        "title": todo["title"],
        "description": todo["description"]
    }

def user_serializer(user)->dict:
    return{
        "id":str(user["_id"]),
        "email":user["email"],
    }

async def db_create_todo(data : dict) -> Union[dict, bool]:
    todo = await collection_todo.insert_one(data)
    new_todo = await collection_todo.find_one({"_id": todo.inserted_id})
    if new_todo:
        return todo_serializer(new_todo)
    return False

async def db_get_todos() ->list:
    todos=[]
    for todo in await collection_todo.find().to_list(length=100):
        todos.append(todo_serializer(todo))
    return todos

async def db_get_single_todo(id:str) ->Union[dict,bool]:
    todo=await collection_todo.find_one({"_id":ObjectId(id)})
    if todo:
        return todo_serializer(todo)
    return False

async def db_update_todo(id:str,data:dict)->Union[dict,bool]:#更新して返す
    todo=await collection_todo.find_one({"_id":ObjectId(id)})#find_one→あるか確認して動かす
    if todo:
        updated_todo=await collection_todo.update_one(#update_one→対象をupdate
            {"_id":ObjectId(id)},{"$set":data}
        )
        if (updated_todo.modified_count >0):#更新が行われるとcountが増えるのでifの条件に
            new_todo=await collection_todo.find_one({"_id":ObjectId(id)})
            return todo_serializer(new_todo)
        return False
    

async def db_delete_todo(id:str)->bool:
    todo=await collection_todo.find_one({"_id":ObjectId(id)})
    if todo:
        deleted_todo=await collection_todo.delete_one({"_id":ObjectId(id)})
        if (deleted_todo.deleted_count>0):#デリートでも消したらカウントされるのでifに
            return True
    return False

async def db_singup(data:dict)->dict:#新しくユーザーを作るところ
    email=data.get("email")
    password=data.get("password")
    overlap_user=await collection_user.find_one({"email":email})#Eメールでかぶってる人がいるか探す
    if overlap_user:
        raise HTTPException(status_code=400,detail='Email is already taken')
    if not password or len(password)<6:#パスワードが入力されていないor６文字以下
        raise HTTPException(status_code=400,detai='Password too short')
    user =await collection_user.insert_one({"email":email,"password":auth.generate_hashed_pw(password)})
    #↑データベースにパスワードとEメールを登録
    new_user=await collection_user.find_one({"_id":user.inserted_id})
    return user_serializer(new_user)

async def db_login(data:dict)->str:
    email=data.get("email")
    password=data.get("password")
    user=await collection_user.find_one({"email":email})#emailに対応するユーザーを探す
    if not user or not auth.verify_pw(password,user["password"]):#そのユーザーが存在しないorパスワードが違うなら
        raise HTTPException(
            status_code=401,detail='Invalid email or password')
    token=auth.encode_jwt(user['email'])
    return token







