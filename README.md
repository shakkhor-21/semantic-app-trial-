# FastAPI Document Management App

A role-based FastAPI web app with:
- **Admin panel** for managing users and all documents.
- **User panel** for managing each user's own documents.

## Features

- Login with `user_id` + password.
- Session-based authentication.
- Admin can:
  - View all documents.
  - Create new documents.
  - Edit any document.
  - Create/edit users.
- User can:
  - View their own documents.
  - Create new documents.
  - Edit/delete their own documents.

## Quick Start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Then open: `http://127.0.0.1:8000`

## Default Admin

On first run, a default admin is created automatically:

- `user_id`: `admin`
- `password`: `admin123`

> Change it from **Admin → Manage Users → Edit** as soon as possible.
