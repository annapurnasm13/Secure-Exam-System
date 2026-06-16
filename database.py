import hashlib
import hmac
import secrets
import sqlite3

DB_PATH = 'database.db'


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('ascii'), 120000)
    return f'pbkdf2_sha256${salt}${digest.hex()}'


conn = sqlite3.connect(DB_PATH)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS papers(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    release_time TEXT NOT NULL
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS logs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    filename TEXT NOT NULL,
    timestamp TEXT NOT NULL
)
''')

for username, password, role in [('admin', 'admin123', 'admin'), ('faculty', 'faculty123', 'faculty')]:
    cursor.execute('DELETE FROM users WHERE username=?', (username,))
    cursor.execute(
        'INSERT INTO users(username, password, role) VALUES(?, ?, ?)',
        (username, hash_password(password), role),
    )

conn.commit()
conn.close()

print('Database created successfully')
