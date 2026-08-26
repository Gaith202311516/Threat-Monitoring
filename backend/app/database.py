import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, MetaData

load_dotenv()  # تحميل المتغيرات من ملف .env

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://postgres:postgres@localhost:5432/threat_db")
engine = create_engine(DATABASE_URL)
metadata = MetaData()