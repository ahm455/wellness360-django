import pyodbc
from contextlib import contextmanager
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

def get_db_connection():
    try:
        conn = pyodbc.connect(
            r'DRIVER={ODBC Driver 17 for SQL Server};'
            r'SERVER=.\SQLEXPRESS;'
            r'DATABASE=wellness360;'
            r'Trusted_Connection=yes;'
            r'Connection Timeout=30;'
        )
        return conn
    except Exception as e:
        logger.error(f"Database connection failed: {e}")
        raise

@contextmanager
def db_cursor():
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error("DB error:", exc_info=True)
        raise
    finally:
        cursor.close()
        conn.close()
