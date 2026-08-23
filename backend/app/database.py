from sqlalchemy import create_engine, MetaData

# رابط الاتصال بـ PostgreSQL (تأكد من اسم المستخدم وكلمة المرور التي أنشأتها)
DATABASE_URL = "postgresql://threat_user:secure_password@localhost:5432/threat_db"

engine = create_engine(DATABASE_URL)
metadata = MetaData()