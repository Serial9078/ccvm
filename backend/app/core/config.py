import os

DB_HOST = os.getenv("DB_HOST", "postgres")
DB_NAME = os.getenv("DB_NAME", "ccvm")
DB_USER = os.getenv("DB_USER", "ccvm")
DB_PASS = os.getenv("DB_PASS", "ChangeMeStrongPassword")

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:5432/{DB_NAME}"
