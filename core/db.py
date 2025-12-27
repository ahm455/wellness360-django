import sqlite3
from contextlib import contextmanager
from pathlib import Path
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

# SQLite database path
DB_PATH = Path(settings.BASE_DIR) / "db.sqlite3"

def get_db_connection():
    try:
        conn = sqlite3.connect(DB_PATH)
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
        
