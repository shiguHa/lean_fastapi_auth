import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm 
from jose import JWTError, jwt
from passlib.context import CryptContext


# --- 設定 ---
# 本番環境ではもっと複雑なキーを使用し、環境変数などから読み込みます
SECRET_KEY = "your-super-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- FastAPIインスタンスとテンプレート ---
app = FastAPI()
templates = Jinja2Templates(directory="templates")

# --- パスワードハッシュ化 ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- モックデータベース ---
# 実際のアプリケーションでは、ちゃんとしたデータベースを使用します
FAKE_USERS_DB = {
    "user1": {
        "username": "user1",
        "full_name": "Taro Yamada",
        "email": "user1@example.com",
        "hashed_password": pwd_context.hash("password123"), # password is "password123"
        "disabled": False,
    }
}

# クライアント情報 (IDとシークレット)
FAKE_CLIENTS_DB = {
    # Authorization Code Flow で使用するWebアプリクライアント
    "web-app-client-id": {
        "secret": "web-app-client-secret",
        "redirect_uri": "http://localhost:8000/callback" # クライアントアプリのコールバックURL
    },
    # Client Credentials Flow で使用するPLCクライアント
    "plc-client-id": {
         "secret": "plc-client-secret"
    }
}

# 認可コードを一時的に保存する場所
AUTH_CODES: Dict[str, Dict[str, Any]] = {}

# --- ヘルパー関数 ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- 依存性 (Dependency) ---
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_subject(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        subject: str = payload.get("sub")
        if subject is None:
            raise credentials_exception
        return subject
    except JWTError:
        raise credentials_exception

# --- 認可サーバーのエンドポイント ---

# 1. (Authorization Code Flow) ユーザーに認可を求める画面
@app.get("/authorize", response_class=HTMLResponse)
async def get_authorization_page(request: Request, client_id: str, redirect_uri: str):
    if client_id not in FAKE_CLIENTS_DB or FAKE_CLIENTS_DB[client_id]["redirect_uri"] != redirect_uri:
        raise HTTPException(status_code=400, detail="Invalid client or redirect URI")
    return templates.TemplateResponse("consent.html", {"request": request, "client_id": client_id, "redirect_uri": redirect_uri})

# 2. (Authorization Code Flow) ユーザーがログインして認可コードを発行
@app.post("/authorize")
async def handle_login_for_authorization(
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...)
):
    user = FAKE_USERS_DB.get(username)
    if not user or not pwd_context.verify(password, user["hashed_password"]):
         raise HTTPException(status_code=400, detail="Incorrect username or password")

    # 認可コードを生成して保存
    auth_code = secrets.token_urlsafe(32)
    AUTH_CODES[auth_code] = {"username": username, "client_id": client_id, "used": False}

    # クライアントにリダイレクト
    return RedirectResponse(f"{redirect_uri}?code={auth_code}", status_code=302)


# 3. 両方のフローで使われるトークン発行エンドポイント
@app.post("/token")
# (C) /token エンドポイントでは、フォームデータを受け取るために `OAuth2PasswordRequestForm` を使う
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = FAKE_USERS_DB.get(form_data.username)
    if not user or user["password"] != form_data.password:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/token")
async def get_token(
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None)
):
    # クライアント認証
    client = FAKE_CLIENTS_DB.get(client_id)
    if not client or client["secret"] != client_secret:
        raise HTTPException(status_code=400, detail="Invalid client credentials")

    # --- grant_type で処理を分岐 ---
    if grant_type == "authorization_code":
        if not code or code not in AUTH_CODES:
            raise HTTPException(status_code=400, detail="Invalid authorization code")
        
        auth_code_data = AUTH_CODES[code]
        if auth_code_data["client_id"] != client_id or auth_code_data["used"]:
            raise HTTPException(status_code=400, detail="Invalid or used authorization code")
        
        # 認可コードを使用済みにする
        AUTH_CODES[code]["used"] = True
        
        # ユーザーのためのアクセストークンを発行
        subject = f"user:{auth_code_data['username']}"
        access_token = create_access_token(
            data={"sub": subject},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": access_token, "token_type": "bearer"}

    elif grant_type == "client_credentials":
        # マシンのためのアクセストークンを発行
        subject = f"client:{client_id}"
        access_token = create_access_token(
            data={"sub": subject},
            expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        )
        return {"access_token": access_token, "token_type": "bearer"}

    else:
        raise HTTPException(status_code=400, detail="Unsupported grant type")

# --- コールバック用 (デモのため) ---
@app.get("/callback")
async def callback(code: str):
    return {"message": "Authorization code received. Now exchange it for a token.", "code": code}

# --- リソースサーバー（保護されたAPI）のエンドポイント ---

# Authorization Code Flow で取得したトークンでアクセスするAPI
@app.get("/users/me")
async def read_users_me(subject: str = Depends(get_current_subject)):
    if not subject.startswith("user:"):
        raise HTTPException(status_code=403, detail="Permission denied: User token required")
    username = subject.split(":", 1)[1]
    user = FAKE_USERS_DB.get(username)
    return user

# Client Credentials Flow で取得したトークンでアクセスするAPI
@app.post("/plc/data")
async def receive_plc_data(data: Dict, subject: str = Depends(get_current_subject)):
    if not subject.startswith("client:"):
        raise HTTPException(status_code=403, detail="Permission denied: Client token required")
    client_id = subject.split(":", 1)[1]
    print(f"Received data from client '{client_id}': {data}")
    return {"message": "Data received successfully", "client_id": client_id, "received_data": data}

#
# <<< ✨✨ ここからが追加した共有エンドポイントです ✨✨ >>>
#
@app.get("/shared/info")
async def read_shared_info(subject: str = Depends(get_current_subject)):
    """
    このエンドポイントは、トークンが有効であれば、
    ユーザー/クライアントの種類を問わずアクセスを許可します。
    """
    return {
        "message": "This is a shared resource. Access GRANTED.",
        "requester_subject": subject
    }

