import sqlite3
import os
from datetime import datetime

# Point to your root 'database' folder
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'database', 'evidence.db')

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Create a table for our uploaded files
    c.execute('''
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT,
            md5 TEXT,
            sha256 TEXT,
            upload_time TEXT
        )
    ''')
    conn.commit()
    conn.close()

def save_evidence(filename, md5, sha256):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute('INSERT INTO evidence (filename, md5, sha256, upload_time) VALUES (?, ?, ?, ?)', 
              (filename, md5, sha256, now))
    conn.commit()
    conn.close()

def get_all_evidence():
    conn = sqlite3.connect(DB_PATH)
    # This makes the database return dictionaries instead of plain lists
    conn.row_factory = sqlite3.Row 
    c = conn.cursor()
    c.execute('SELECT * FROM evidence ORDER BY upload_time DESC')
    rows = c.fetchall()
    conn.close()
    return rows