from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, HTTPException, Depends, status
from sqlmodel import SQLModel, Field, Session, create_engine, select
from jose import jwt
import httpx

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("read data services started")
    yield

app = FastAPI(lifespan=lifespan, title="read data services")

class TokenData(SQLModel):
    iss: str

class Item(SQLModel, table=True):
    id: int = Field(default=None, primary_key=True)
    name: str
    description: str = None

# Database setup
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, echo=True)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

create_db_and_tables()

# JWT settings
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 2

def get_secret_from_kong(consumer_id: str) -> str:
    with httpx.Client() as client:
        print(f'consumer_id: {consumer_id}')
        url = f"http://kong:8001/consumers/{consumer_id}/jwt"
        response = client.get(url)
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code,
                                detail="Failed to fetch secret from Kong")
        kong_data = response.json()
        print(f'Kong Data: {kong_data}')
        if not kong_data['data'][0]["secret"]:
            raise HTTPException(
                status_code=404, detail="No JWT credentials found for the specified consumer")

        secret = kong_data['data'][0]["secret"]
        print(f'Secret: {secret}')
        return secret

def create_jwt_token(data: dict, secret: str):
    to_encode = data.copy()
    expire = datetime.utcnow() + \
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Limit expiration time to 2038-01-19 03:14:07 UTC
    expire = min(expire, datetime(2038, 1, 19, 3, 14, 7))
    to_encode.update({"exp": expire})
    headers = {
        "typ": "JWT",
        "alg": ALGORITHM
    }
    encoded_jwt = jwt.encode(to_encode, secret,
                             algorithm=ALGORITHM, headers=headers)
    return encoded_jwt

@app.post("/generate-token/")
async def generate_token(data: TokenData, consumer_id: str):
    secret = get_secret_from_kong(consumer_id)
    payload = {"iss": data.iss}
    token = create_jwt_token(payload, secret)
    return {"token": token}

# CRUD operations
@app.post("/items/", response_model=Item, status_code=status.HTTP_201_CREATED)
def create_item(item: Item):
    with Session(engine) as session:
        session.add(item)
        session.commit()
        session.refresh(item)
        return item

@app.get("/items/{item_id}", response_model=Item)
def read_item(item_id: int):
    with Session(engine) as session:
        item = session.get(Item, item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Item not found")
        return item

@app.put("/items/{item_id}", response_model=Item)
def update_item(item_id: int, item: Item):
    with Session(engine) as session:
        existing_item = session.get(Item, item_id)
        if not existing_item:
            raise HTTPException(status_code=404, detail="Item not found")
        existing_item.name = item.name
        existing_item.description = item.description
        session.add(existing_item)
        session.commit()
        session.refresh(existing_item)
        return existing_item

@app.delete("/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_item(item_id: int):
    with Session(engine) as session:
        item = session.get(Item, item_id)
        if not item:
            raise HTTPException(status_code=404, detail="Item not found")
        session.delete(item)
        session.commit()
        return
