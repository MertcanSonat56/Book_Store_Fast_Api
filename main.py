import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from schema import Book as SchemaBook
from schema import Author as SchemaAuthor
from models import Book
from models import Author
from models import User
from models import Book as ModelBook
from models import Author as ModelAuthor
from dotenv import load_dotenv
from fastapi_sqlalchemy import DBSessionMiddleware, db
import os
from fastapi.security import JWTAuthentication, JWTBearer
from passlib.context import CryptContext
from datetime import timedelta, datetime
from typing import Optional
from jose import JWTError, jwt

load_dotenv(".env")

app = FastAPI()

SECRET_KEY = "your-secret-key"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
ACCESS_TOKEN_EXPIRE_MINUTES = 30

jwt_authentication = JWTAuthentication(
    secret_key=SECRET_KEY, 
    algorithm="HS256"
)

app.add_middleware(DBSessionMiddleware, db_url=os.environ["DATABASE_URL"])

@app.get("/")
async def root():
    return {"message": "Hello World"}


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def get_current_user(token: str = Depends(JWTBearer(jwt_authentication))):
    try:
        payload = jwt.decode(token.token, SECRET_KEY, algorithms=["HS256"])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    return user


def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    if not pwd_context.verify(password, user.password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/protected")
def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello, {current_user.username}!"}



@app.post("/add-book/", response_model=SchemaBook)
def add_book(book: SchemaBook):
    db_book = ModelBook(title=book.title, rating=book.rating, author_id=book.author_id)
    db.session.add(db_book)
    db.session.commit()
    return db_book

@app.delete("/delete-book/{book_id}", response_model=SchemaBook)
def delete_book(book_id: int):
    db_book = db.session.query(ModelBook).filter(ModelBook.id == book_id).first()
    
    if not db_book:
        raise HTTPException(status_code=404, detail="Book not found")
    db.session.delete(db_book)
    db.session.commit()
    return db_book

@app.put("/update-book/{book_id}", response_model=SchemaBook)
def update_book(book_id: int, book: SchemaBook):
    db_book = db.session.query(ModelBook).filter(ModelBook)

    if not db_book:
        raise HTTPException(status_code=404, detail="Book not found")
    
    db_book.title = book.title
    db_book.rating = book.rating
    db_book.author_id = book.author_id
    db.session.commit()
    return db_book

@app.get("/books/")
def get_books():
    books = db.session.query(Book).all()
    return books


@app.post("/add-author/", response_model=SchemaAuthor)
def add_author(author: SchemaAuthor):
    db_author = ModelAuthor(name=author.name, age=author.age)
    db.session.add(db_author)
    db.session.commit()
    return db_author


@app.get("/author/")
def get_author():
    author = db.session.query(Author).all()
    return author

  
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)











