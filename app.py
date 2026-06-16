import os
import re
import html
import hmac
import time
import secrets
import hashlib
import sqlite3
import mimetypes
from datetime import datetime
from http import cookies
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote
from utils.encryption import encrypt_file, decrypt_file

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / 'database.db'
TEMPLATE_DIR = BASE_DIR / 'templates'
STATIC_DIR = BASE_DIR / 'static'
UPLOAD_DIR = BASE_DIR / 'encrypted_files'
SESSION_COOKIE = 'secure_exam_session'
SESSIONS = {}
LEGACY_ENCRYPTION_MAGIC = b'SES2'


def db_connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('ascii'), 120000)
    return f'pbkdf2_sha256${salt}${digest.hex()}'


def verify_password(password, stored):
    if isinstance(stored, bytes):
        try:
            stored = stored.decode('utf-8')
        except UnicodeDecodeError:
            return False
    if not isinstance(stored, str) or not stored.startswith('pbkdf2_sha256$'):
        return False
    try:
        _, salt, _ = stored.split('$', 2)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


def init_database():
    UPLOAD_DIR.mkdir(exist_ok=True)
    with db_connect() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS papers(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                release_time TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS logs(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                filename TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        ''')
        for username, password, role in [('admin', 'admin123', 'admin'), ('faculty', 'faculty123', 'faculty')]:
            conn.execute('DELETE FROM users WHERE username=?', (username,))
            conn.execute(
                'INSERT INTO users(username, password, role) VALUES(?, ?, ?)',
                (username, hash_password(password), role),
            )
        deduplicate_papers(conn)
        conn.execute('CREATE UNIQUE INDEX IF NOT EXISTS idx_papers_filename ON papers(filename)')
        conn.commit()
        clear_legacy_encrypted_files(conn)
        deduplicate_papers(conn)
        conn.commit()


def clear_legacy_encrypted_files(conn):
    legacy_filenames = []
    for path in UPLOAD_DIR.glob('*.enc'):
        if path.read_bytes()[:4] == LEGACY_ENCRYPTION_MAGIC:
            legacy_filenames.append(path.name)
            path.unlink()

    for filename in legacy_filenames:
        conn.execute('DELETE FROM papers WHERE filename=?', (filename,))
        conn.execute('DELETE FROM logs WHERE filename=?', (filename,))


def canonical_encrypted_name(filename):
    filename = clean_filename(filename)
    return filename if filename.endswith('.enc') else f'{filename}.enc'


def display_paper_name(filename):
    return filename[:-4] if filename.endswith('.enc') else filename


def deduplicate_papers(conn):
    duplicate_ids = [
        row['id']
        for row in conn.execute('''
            SELECT id FROM (
                SELECT
                    id,
                    ROW_NUMBER() OVER (PARTITION BY filename ORDER BY id DESC) AS row_number
                FROM papers
            )
            WHERE row_number > 1
        ''')
    ]
    if duplicate_ids:
        placeholders = ','.join('?' for _ in duplicate_ids)
        conn.execute(f'DELETE FROM papers WHERE id IN ({placeholders})', duplicate_ids)


def escape(value):
    return html.escape(str(value), quote=True)


def render_template(name, **context):
    text = (TEMPLATE_DIR / name).read_text(encoding='utf-8')

    def render_loop(match):
        item_name, list_name, body = match.group(1), match.group(2), match.group(3)
        output = []
        for item in context.get(list_name, []):
            local = dict(context)
            local[item_name] = item
            output.append(render_vars(body, local))
        return ''.join(output)

    text = re.sub(r'{%\s*for\s+(\w+)\s+in\s+(\w+)\s*%}(.*?){%\s*endfor\s*%}', render_loop, text, flags=re.S)
    return render_vars(text, context).encode('utf-8')


def resolve_expr(expr, context):
    expr = expr.strip()
    if '[' in expr and expr.endswith(']'):
        base, index = expr[:-1].split('[', 1)
        value = context.get(base.strip(), '')
        try:
            return value[int(index)]
        except (IndexError, ValueError, TypeError):
            return ''
    if '.' in expr:
        value = context
        for part in expr.split('.'):
            if isinstance(value, dict):
                value = value.get(part, '')
            else:
                value = getattr(value, part, '')
        return value
    return context.get(expr, '')


def render_vars(text, context):
    return re.sub(r'{{\s*(.*?)\s*}}', lambda m: escape(resolve_expr(m.group(1), context)), text)


def paper_view(row):
    filename = row['filename']
    return {
        'filename': filename,
        'display_name': display_paper_name(filename),
        'download_path': quote(filename),
    }


def clean_filename(filename):
    filename = Path(filename).name.strip().replace('\x00', '')
    filename = re.sub(r'[^A-Za-z0-9._ -]', '_', filename)
    return filename or f'paper_{int(time.time())}.bin'


def parse_multipart(body, content_type):
    match = re.search(r'boundary=(?P<boundary>[^;]+)', content_type)
    if not match:
        return {}, {}
    boundary = ('--' + match.group('boundary').strip('"')).encode('utf-8')
    fields = {}
    files = {}
    for part in body.split(boundary):
        part = part.strip(b'\r\n')
        if not part or part == b'--':
            continue
        header_blob, _, payload = part.partition(b'\r\n\r\n')
        headers = header_blob.decode('utf-8', 'replace')
        disposition = re.search(r'name="([^"]+)"(?:;\s*filename="([^"]*)")?', headers)
        if not disposition:
            continue
        name, filename = disposition.group(1), disposition.group(2)
        payload = payload.rstrip(b'\r\n')
        if filename is None:
            fields[name] = payload.decode('utf-8', 'replace')
        else:
            files[name] = {'filename': clean_filename(filename), 'data': payload}
    return fields, files


def add_log(username, action, filename):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with db_connect() as conn:
        conn.execute(
            'INSERT INTO logs(username, action, filename, timestamp) VALUES(?, ?, ?, ?)',
            (username, action, filename, timestamp),
        )
        conn.commit()


class SecureExamHandler(BaseHTTPRequestHandler):
    server_version = 'SecureExamSystem/2.0'

    def current_user(self):
        raw_cookie = self.headers.get('Cookie', '')
        jar = cookies.SimpleCookie(raw_cookie)
        morsel = jar.get(SESSION_COOKIE)
        if morsel is None:
            return None
        session = SESSIONS.get(morsel.value)
        if not session:
            return None
        return session.get('username')

    def send_bytes(self, data, status=200, content_type='text/html; charset=utf-8', headers=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        if headers:
            for key, value in headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location):
        self.send_response(303)
        self.send_header('Location', location)
        self.end_headers()

    def require_login(self):
        username = self.current_user()
        if not username:
            self.redirect('/')
            return None
        return username

    def do_GET(self):
        path = unquote(self.path.split('?', 1)[0])
        if path == '/':
            return self.send_bytes(render_template('index.html'))
        if path.startswith('/static/'):
            return self.serve_static(path)
        if path == '/admin':
            if self.require_login() is None:
                return
            return self.send_bytes(render_template('admin.html'))
        if path == '/faculty':
            if self.require_login() is None:
                return
            with db_connect() as conn:
                papers = [paper_view(row) for row in conn.execute('SELECT filename FROM papers ORDER BY id DESC')]
            return self.send_bytes(render_template('faculty.html', papers=papers))
        if path == '/dashboard':
            if self.require_login() is None:
                return
            with db_connect() as conn:
                uploads = conn.execute("SELECT COUNT(*) FROM logs WHERE action='Uploaded'").fetchone()[0]
                downloads = conn.execute("SELECT COUNT(*) FROM logs WHERE action='Downloaded'").fetchone()[0]
                users = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
                recent_logs = [tuple(row) for row in conn.execute('SELECT username, action, filename, timestamp FROM logs ORDER BY id DESC LIMIT 5')]
            return self.send_bytes(render_template('dashboard.html', uploads=uploads, downloads=downloads, users=users, recent_logs=recent_logs))
        if path == '/logs':
            if self.require_login() is None:
                return
            with db_connect() as conn:
                logs = [tuple(row) for row in conn.execute('SELECT * FROM logs ORDER BY id DESC')]
            return self.send_bytes(render_template('logs.html', logs=logs))
        if path == '/logout':
            raw_cookie = self.headers.get('Cookie', '')
            jar = cookies.SimpleCookie(raw_cookie)
            morsel = jar.get(SESSION_COOKIE)
            if morsel is not None:
                SESSIONS.pop(morsel.value, None)
            self.send_response(303)
            self.send_header('Location', '/')
            self.send_header('Set-Cookie', f'{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax')
            self.end_headers()
            return
        if path.startswith('/download/'):
            return self.download_form(path.removeprefix('/download/'))
        self.send_error(404)

    def do_POST(self):
        path = self.path.split('?', 1)[0]
        length = int(self.headers.get('Content-Length', '0'))
        body = self.rfile.read(length)
        content_type = self.headers.get('Content-Type', '')
        if path == '/login':
            fields = parse_qs(body.decode('utf-8', 'replace'))
            username = fields.get('username', [''])[0]
            password = fields.get('password', [''])[0]
            with db_connect() as conn:
                user = conn.execute('SELECT username, password, role FROM users WHERE username=? ORDER BY id DESC', (username,)).fetchone()
            if user and verify_password(password, user['password']):
                session_id = secrets.token_urlsafe(32)
                SESSIONS[session_id] = {'username': username, 'role': user['role']}
                self.send_response(303)
                self.send_header('Location', '/admin' if user['role'] == 'admin' else '/faculty')
                self.send_header('Set-Cookie', f'{SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax')
                self.end_headers()
                return
            return self.send_bytes(b'Invalid Username or Password', status=401, content_type='text/plain; charset=utf-8')
        if path == '/upload':
            return self.upload_file(body, content_type)
        if path == '/download':
            fields = parse_qs(body.decode('utf-8', 'replace'))
            filename = fields.get('filename', [''])[0]
            passphrase = fields.get('passphrase', [''])[0]
            return self.download_file(filename, passphrase)
        self.send_error(404)

    def upload_file(self, body, content_type):
        username = self.require_login()
        if username is None:
            return
        fields, files = parse_multipart(body, content_type)
        uploaded = files.get('file')
        release_time = fields.get('release_time', '')
        passphrase = fields.get('passphrase', '')
        if not uploaded or not release_time or not passphrase:
            return self.send_bytes(b'Missing file, release time, or passphrase.', status=400, content_type='text/plain; charset=utf-8')
        try:
            datetime.strptime(release_time, '%Y-%m-%dT%H:%M')
        except ValueError:
            return self.send_bytes(b'Invalid release time format.', status=400, content_type='text/plain; charset=utf-8')
        encrypted_name = canonical_encrypted_name(uploaded['filename'])
        target = UPLOAD_DIR / encrypted_name
        try:
            encrypted_data = encrypt_file(uploaded['data'], passphrase)
        except ValueError as exc:
            return self.send_bytes(str(exc).encode('utf-8'), status=400, content_type='text/plain; charset=utf-8')
        target.write_bytes(encrypted_data)
        with db_connect() as conn:
            conn.execute('''
                INSERT INTO papers(filename, release_time) VALUES(?, ?)
                ON CONFLICT(filename) DO UPDATE SET release_time=excluded.release_time
            ''', (target.name, release_time))
            conn.commit()
        add_log(username, 'Uploaded', target.name)
        self.send_bytes(b'File encrypted and locked until release time.', content_type='text/plain; charset=utf-8')

    def download_form(self, filename):
        if self.require_login() is None:
            return
        filename = clean_filename(filename)
        return self.send_bytes(render_template('download.html', filename=filename))

    def download_file(self, filename, passphrase):
        username = self.require_login()
        if username is None:
            return
        filename = clean_filename(filename)
        with db_connect() as conn:
            paper = conn.execute('SELECT release_time FROM papers WHERE filename=?', (filename,)).fetchone()
        if paper is None:
            return self.send_bytes(b'File not found.', status=404, content_type='text/plain; charset=utf-8')
        release_time = datetime.strptime(paper['release_time'], '%Y-%m-%dT%H:%M')
        if datetime.now() < release_time:
            return self.send_bytes(b'Access denied. Paper is not released yet.', status=403, content_type='text/plain; charset=utf-8')
        path = UPLOAD_DIR / filename
        if not path.exists():
            return self.send_bytes(b'File is registered but missing on disk.', status=404, content_type='text/plain; charset=utf-8')
        original_name = filename[:-4] if filename.endswith('.enc') else filename
        try:
            data = decrypt_file(path.read_bytes(), passphrase)
        except ValueError as exc:
            return self.send_bytes(str(exc).encode('utf-8'), status=403, content_type='text/plain; charset=utf-8')
        add_log(username, 'Downloaded', filename)
        mime = mimetypes.guess_type(original_name)[0] or 'application/octet-stream'
        headers = {'Content-Disposition': f'attachment; filename="{original_name}"'}
        self.send_bytes(data, content_type=mime, headers=headers)

    def serve_static(self, path):
        name = clean_filename(path.removeprefix('/static/'))
        target = STATIC_DIR / name
        if not target.exists() or not target.is_file():
            return self.send_error(404)
        mime = mimetypes.guess_type(name)[0] or 'application/octet-stream'
        self.send_bytes(target.read_bytes(), content_type=mime)


def run():
    init_database()
    host = '127.0.0.1'
    port = 5000
    httpd = ThreadingHTTPServer((host, port), SecureExamHandler)
    print(f'Secure Exam System running at http://{host}:{port}')
    print('Default logins: admin/admin123 and faculty/faculty123')
    httpd.serve_forever()


if __name__ == '__main__':
    run()

