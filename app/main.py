from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from passlib.context import CryptContext
from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, create_engine, select
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker
from starlette.middleware.sessions import SessionMiddleware

BASE_DIR = Path(__file__).resolve().parent
DATABASE_URL = f"sqlite:///{BASE_DIR / 'app.db'}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    documents: Mapped[list[Document]] = relationship("Document", back_populates="owner", cascade="all, delete-orphan")


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False, index=True)

    owner: Mapped[User] = relationship("User", back_populates="documents")


app = FastAPI(title="Document Management App")
app.add_middleware(SessionMiddleware, secret_key="change-this-secret-key")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static"), check_dir=False), name="static")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    user = db.scalar(select(User).where(User.id == user_id))
    if not user:
        request.session.clear()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return user


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        admin_exists = db.scalar(select(User).where(User.user_id == "admin"))
        if not admin_exists:
            admin = User(user_id="admin", password_hash=hash_password("admin123"), is_admin=True)
            db.add(admin)
            db.commit()


@app.get("/")
def home(request: Request, db: Session = Depends(get_db)):
    session_user_id = request.session.get("user_id")
    if not session_user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    user = db.scalar(select(User).where(User.id == session_user_id))
    if not user:
        request.session.clear()
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    target = "/admin" if user.is_admin else "/user"
    return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)


@app.get("/login")
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
def login(
    request: Request,
    user_id: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.user_id == user_id.strip()))
    if not user or not verify_password(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "error": "Invalid credentials"},
            status_code=status.HTTP_401_UNAUTHORIZED,
        )

    request.session["user_id"] = user.id
    target = "/admin" if user.is_admin else "/user"
    return RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)


@app.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin")
def admin_dashboard(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    documents = db.scalars(select(Document).order_by(Document.id.desc())).all()
    return templates.TemplateResponse(
        "admin_dashboard.html",
        {"request": request, "admin": admin, "documents": documents},
    )


@app.get("/admin/documents/new")
def admin_new_document_page(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.user_id.asc())).all()
    return templates.TemplateResponse(
        "admin_document_form.html",
        {
            "request": request,
            "admin": admin,
            "users": users,
            "document": None,
            "action": "Create",
        },
    )


@app.post("/admin/documents/new")
def admin_create_document(
    request: Request,
    owner_id: int = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    summary: str = Form(""),
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    owner = db.scalar(select(User).where(User.id == owner_id))
    if not owner:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Owner not found")

    doc = Document(
        owner_id=owner.id,
        title=title.strip(),
        description=description.strip(),
        summary=summary.strip(),
    )
    db.add(doc)
    db.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin/documents/{doc_id}/edit")
def admin_edit_document_page(
    doc_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    doc = db.scalar(select(Document).where(Document.id == doc_id))
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    users = db.scalars(select(User).order_by(User.user_id.asc())).all()
    return templates.TemplateResponse(
        "admin_document_form.html",
        {
            "request": request,
            "admin": admin,
            "users": users,
            "document": doc,
            "action": "Edit",
        },
    )


@app.post("/admin/documents/{doc_id}/edit")
def admin_edit_document(
    doc_id: int,
    owner_id: int = Form(...),
    title: str = Form(...),
    description: str = Form(""),
    summary: str = Form(""),
    _: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    doc = db.scalar(select(Document).where(Document.id == doc_id))
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    owner = db.scalar(select(User).where(User.id == owner_id))
    if not owner:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Owner not found")

    doc.owner_id = owner.id
    doc.title = title.strip()
    doc.description = description.strip()
    doc.summary = summary.strip()
    db.commit()
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin/users")
def admin_users_page(request: Request, admin: User = Depends(require_admin), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.id.asc())).all()
    return templates.TemplateResponse("admin_users.html", {"request": request, "admin": admin, "users": users})


@app.get("/admin/users/new")
def admin_new_user_page(request: Request, admin: User = Depends(require_admin)):
    return templates.TemplateResponse(
        "admin_user_form.html",
        {"request": request, "admin": admin, "user": None, "action": "Create", "error": None},
    )


@app.post("/admin/users/new")
def admin_create_user(
    request: Request,
    user_id: str = Form(...),
    password: str = Form(...),
    is_admin: Optional[str] = Form(None),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    normalized_id = user_id.strip()
    if db.scalar(select(User).where(User.user_id == normalized_id)):
        return templates.TemplateResponse(
            "admin_user_form.html",
            {"request": request, "admin": admin, "user": None, "action": "Create", "error": "User ID already exists."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    new_user = User(
        user_id=normalized_id,
        password_hash=hash_password(password),
        is_admin=is_admin == "on",
    )
    db.add(new_user)
    db.commit()
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/admin/users/{user_db_id}/edit")
def admin_edit_user_page(
    user_db_id: int,
    request: Request,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.id == user_db_id))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return templates.TemplateResponse(
        "admin_user_form.html",
        {"request": request, "admin": admin, "user": user, "action": "Edit", "error": None},
    )


@app.post("/admin/users/{user_db_id}/edit")
def admin_edit_user(
    user_db_id: int,
    request: Request,
    user_id: str = Form(...),
    password: str = Form(""),
    is_admin: Optional[str] = Form(None),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    user = db.scalar(select(User).where(User.id == user_db_id))
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    normalized_id = user_id.strip()
    existing = db.scalar(select(User).where(User.user_id == normalized_id))
    if existing and existing.id != user.id:
        return templates.TemplateResponse(
            "admin_user_form.html",
            {"request": request, "admin": admin, "user": user, "action": "Edit", "error": "User ID already exists."},
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    user.user_id = normalized_id
    user.is_admin = is_admin == "on"
    if password.strip():
        user.password_hash = hash_password(password)

    db.commit()
    return RedirectResponse(url="/admin/users", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/user")
def user_dashboard(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    docs = db.scalars(
        select(Document).where(Document.owner_id == user.id).order_by(Document.id.desc())
    ).all()
    return templates.TemplateResponse("user_dashboard.html", {"request": request, "user": user, "documents": docs})


@app.get("/user/documents/new")
def user_new_document_page(request: Request, user: User = Depends(get_current_user)):
    return templates.TemplateResponse(
        "user_document_form.html",
        {"request": request, "user": user, "document": None, "action": "Create"},
    )


@app.post("/user/documents/new")
def user_create_document(
    title: str = Form(...),
    description: str = Form(""),
    summary: str = Form(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = Document(
        owner_id=user.id,
        title=title.strip(),
        description=description.strip(),
        summary=summary.strip(),
    )
    db.add(doc)
    db.commit()
    return RedirectResponse(url="/user", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/user/documents/{doc_id}/edit")
def user_edit_document_page(
    doc_id: int,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = db.scalar(select(Document).where(Document.id == doc_id, Document.owner_id == user.id))
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    return templates.TemplateResponse(
        "user_document_form.html",
        {"request": request, "user": user, "document": doc, "action": "Edit"},
    )


@app.post("/user/documents/{doc_id}/edit")
def user_edit_document(
    doc_id: int,
    title: str = Form(...),
    description: str = Form(""),
    summary: str = Form(""),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = db.scalar(select(Document).where(Document.id == doc_id, Document.owner_id == user.id))
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    doc.title = title.strip()
    doc.description = description.strip()
    doc.summary = summary.strip()
    db.commit()
    return RedirectResponse(url="/user", status_code=status.HTTP_303_SEE_OTHER)


@app.post("/user/documents/{doc_id}/delete")
def user_delete_document(
    doc_id: int,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    doc = db.scalar(select(Document).where(Document.id == doc_id, Document.owner_id == user.id))
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    db.delete(doc)
    db.commit()
    return RedirectResponse(url="/user", status_code=status.HTTP_303_SEE_OTHER)
