# Проверка подключения к БД
from extensions import db
def test_database_connection():
    try:
        db.engine.connect()
        print("Database connection successful!")
    except Exception as e:
        print(f"Database connection failed: {str(e)}")