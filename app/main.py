import httpx
from .model import Users
from sqlmodel import Session, select
from .db import create_tables, engine
from fastapi.responses import RedirectResponse
import uvicorn
from fastapi import FastAPI, Depends, HTTPException, Security
from jose import jwt, JWTError
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer, OAuth2AuthorizationCodeBearer, SecurityScopes
from typing import Annotated, List
import os
from dotenv import load_dotenv
from googleapiclient.discovery import build
from google.auth.credentials import Credentials
from email.mime.text import MIMEText
import base64
load_dotenv()

ALGORITHM = os.getenv("ALGORITHM")
SECRET_KEY = os.getenv("SECRET_KEY")
# Githhub Keys
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI")
# Google Keys
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_PROJECT_ID = os.getenv("GOOGLE_PROJECT_ID")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI")
GOOGLE_TOKEN_URL = os.getenv("GOOGLE_TOKEN_URL")


app = FastAPI()

# oauth2 Schema
oauth2_password_scheme = OAuth2PasswordBearer(tokenUrl="login")
google_oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://accounts.google.com/o/oauth2/auth",
    tokenUrl="https://oauth2.googleapis.com/token"
)

github_oauth2_scheme = OAuth2AuthorizationCodeBearer(
    authorizationUrl="https://github.com/login/oauth/authorize",
    tokenUrl="https://github.com/login/oauth/access_token"
)


# Google Login
@app.get('/google-login')
async def google_login():
    return RedirectResponse(f"https://accounts.google.com/o/oauth2/auth?response_type=code&client_id={GOOGLE_CLIENT_ID}&redirect_uri={GOOGLE_REDIRECT_URI}&scope=openid%20profile%20email%20https://www.googleapis.com/auth/gmail.modify&access_type=offline")

# Google authentication callback function


@app.get("/auth/google")
async def auth_google(code: str):
    token_url = "https://accounts.google.com/o/oauth2/token"
    params = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }
    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient() as client:
        response = await client.post(token_url, params=params, headers=headers)
        access_token_response = response.json()
        token = access_token_response['access_token']
    async with httpx.AsyncClient() as client:
        headers.update({'Authorization': f"Bearer {token}"})
        response = await client.get('https://www.googleapis.com/oauth2/v1/userinfo', headers=headers)
        data_from_google = response.json()
        email_from_google = data_from_google['email']
        name_from_google = data_from_google.get('name', email_from_google)
    # Handle user
    with Session(engine) as session:
        user = session.exec(select(Users).where(Users.email == email_from_google)).first()
        if not user:
            user = Users(userName=email_from_google, name=name_from_google, email=email_from_google, password="", google_access_token=token)
            session.add(user)
        else:
            user.google_access_token = token
        session.commit()
        session.refresh(user)
    # token creation using email from google
    access_token_expire = timedelta(minutes=10)
    for_token = email_from_google
    expire = datetime.utcnow() + access_token_expire
    to_encode = {"exp": expire, "sub": str(for_token)}
    jwt_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return {"access token": jwt_token, "token_type": "bearer", "expire_in": expire}


# GitHub Login
@app.get('/github-login')
async def github_login():
    return RedirectResponse(f"https://github.com/login/oauth/authorize?client_id={GITHUB_CLIENT_ID}", status_code=302)

# github calback function


@app.get("/auth/callback")
async def auth_callback(code: str):
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code
    }
    headers = {"Accept": "application/json"}
    async with httpx.AsyncClient() as client:
        response = await client.post(url="https://github.com/login/oauth/access_token", params=params, headers=headers)
    response_json = response.json()
    # print(response_json)
    token = response_json['access_token']
    # print(token)
    async with httpx.AsyncClient() as client:
        headers.update({'Authorization': f"Bearer {token}"})
        response = await client.get('https://api.github.com/user', headers=headers)
        data_from_github = response.json()
# fetch username from github/user
        username = data_from_github['login']
# token creation using github username
        access_token_expire = timedelta(minutes=10)
        for_token = username
        expire = datetime.utcnow() + access_token_expire
        to_encode = {"exp": expire, "sub": str(for_token)}
        access_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return {"access token": access_token, "token_type": "bearer", "expire_in": expire}
        # return RedirectResponse(f"http://127.0.0.1:8080/users?token={access_token}")

# Register


@app.post('/resister')
def register(user_data: Users):
    with Session(engine) as session:
        user = session.get(Users, user_data.userName)
        if user:
            raise HTTPException(
                status_code=400, detail="User Is Already Register")
        session.add(user_data)
        session.commit()
        session.refresh(user_data)
        return {'Message': "User Register Sucessfully", "data": user_data}

# login by db


@app.post('/login')
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends(OAuth2PasswordRequestForm)]):
    with Session(engine)as session:
        user_in_fake_db = session.get(Users, form_data.username)
        if not user_in_fake_db:
            raise HTTPException(status_code=400, detail="Incorrect username")
        if not form_data.password == user_in_fake_db.password:
            raise HTTPException(status_code=400, detail="Incorrect password")
        access_token_expire = timedelta(minutes=10)
        for_token = form_data.username
        expire = datetime.utcnow() + access_token_expire
        to_encode = {"exp": expire, "sub": str(for_token)}
        access_token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return {"access token": access_token, "token_type": "bearer", "expire_in": expire}


# Route to get all users
@app.get('/users', response_model=List[Users])
def get_all_user(token: str = Depends(oauth2_password_scheme)):
    with Session(engine) as session:
        user_in_db = session.exec(select(Users)).all()
        return user_in_db


# MCP JSON-RPC endpoint
@app.post("/mcp")
async def mcp_endpoint(request: dict):
    jsonrpc = request.get("jsonrpc")
    method = request.get("method")
    params = request.get("params", {})
    id = request.get("id")

    if jsonrpc != "2.0":
        return {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid Request"}, "id": id}

    # Get user with Google access token
    with Session(engine) as session:
        user = session.exec(select(Users).where(Users.google_access_token.isnot(None))).first()
        if not user:
            return {"jsonrpc": "2.0", "error": {"code": -32000, "message": "No authorized user"}, "id": id}

    creds = Credentials(token=user.google_access_token)
    service = build('gmail', 'v1', credentials=creds)

    try:
        if method == "gmail.send_email":
            if not all(k in params for k in ["to", "subject", "body"]):
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params"}, "id": id}
            to = params["to"]
            subject = params["subject"]
            body = params["body"]
            message = MIMEText(body)
            message['to'] = to
            message['subject'] = subject
            raw = base64.urlsafe_b64encode(message.as_bytes()).decode()
            service.users().messages().send(userId='me', body={'raw': raw}).execute()
            return {"jsonrpc": "2.0", "result": "Email sent", "id": id}

        elif method == "gmail.list_labels":
            labels = service.users().labels().list(userId='me').execute()
            return {"jsonrpc": "2.0", "result": labels.get('labels', []), "id": id}

        elif method == "gmail.search_messages":
            if "query" not in params:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params"}, "id": id}
            query = params["query"]
            results = service.users().messages().list(userId='me', q=query).execute()
            messages = results.get('messages', [])
            result = [{"id": m['id'], "snippet": m.get('snippet', '')} for m in messages]
            return {"jsonrpc": "2.0", "result": result, "id": id}

        elif method == "gmail.get_message":
            if "id" not in params:
                return {"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid params"}, "id": id}
            message_id = params["id"]
            message = service.users().messages().get(userId='me', id=message_id, format='full').execute()
            headers = {h['name']: h['value'] for h in message['payload']['headers']}
            body_data = message['payload'].get('body', {}).get('data', '')
            body = base64.urlsafe_b64decode(body_data).decode() if body_data else ''
            return {"jsonrpc": "2.0", "result": {"headers": headers, "body": body}, "id": id}

        else:
            return {"jsonrpc": "2.0", "error": {"code": -32601, "message": "Method not found"}, "id": id}

    except Exception as e:
        return {"jsonrpc": "2.0", "error": {"code": -32000, "message": str(e)}, "id": id}


def start():
    create_tables()
    uvicorn.run("app.main:app", host="127.0.0.1", port=8080, reload=True)
 
