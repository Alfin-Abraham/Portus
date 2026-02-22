# Standard library imports
import asyncio
import hashlib
import logging
import mimetypes
import os
import platform
import re
import secrets
import shutil
import socket
import subprocess
import threading
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import AsyncGenerator, List, Optional

# Third-party imports
import aiofiles
import uvicorn
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.middleware.sessions import SessionMiddleware
from werkzeug.utils import secure_filename
from zeroconf import ServiceInfo, Zeroconf



if platform.system() == 'Windows':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class _SuppressConnNoise(logging.Filter):
    _NOISE = (
        'WinError 10054',
        'ConnectionResetError',
        'SSL connection is closed',
        'SSL handshake failed',
        'Too little data for declared Content-Length',
    )
    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return not any(phrase in msg for phrase in self._NOISE)


_conn_noise_filter = _SuppressConnNoise()
for _logger_name in ('uvicorn.error', 'uvicorn.access', 'asyncio',
                      'uvicorn.protocols.http.h11_impl',
                      'uvicorn.protocols.http.httptools_impl',
                      'uvicorn.protocols.https'):
    logging.getLogger(_logger_name).addFilter(_conn_noise_filter)


def _custom_asyncio_exception_handler(loop, context):
    """Suppresses non-critical errors"""
    exc = context.get('exception')
    msg = context.get('message', '')

    if isinstance(exc, AssertionError) and 'Data should not be empty' in str(exc):
        return
    if isinstance(exc, (ConnectionResetError, BrokenPipeError)):
        return
    if 'SSL connection is closed' in msg or 'WinError 10054' in msg:
        return
    if isinstance(exc, asyncio.CancelledError) and _server_shutting_down:
        return
    if 'Too little data for declared Content-Length' in str(exc):
        return

    # Everything else: default behaviour (print to stderr)
    loop.default_exception_handler(context)


# ------------------------------
# CONFIGURATION
# ------------------------------

class Config:
    """Application configuration constants."""
    # Server
    PORT = 6080
    HOST = '0.0.0.0'
    DEBUG = False

    # Paths
    SHARED_FILES_FOLDER = 'Portus_Dock'
    TEMP_UPLOADS_FOLDER = os.path.join(SHARED_FILES_FOLDER, '.uploads')
    CERT_DIR = 'Portus_Certificates'
    CERT_FILE = os.path.join(CERT_DIR, 'server_cert.pem')
    KEY_FILE = os.path.join(CERT_DIR, 'server_key.pem')

    # Security
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024 * 1024  # 5 GB
    SESSION_TIMEOUT_MINUTES = 12
    PERMANENT_SESSION_LIFETIME = timedelta(hours=10)

    # File operations
    UPLOAD_CHUNK_SIZE = 3 * 1024 * 1024
    DOWNLOAD_CHUNK_SIZE = 3 * 1024 * 1024
    MAX_CONCURRENT_UPLOADS = 3
    
    # File types allowed
    ALLOWED_EXTENSIONS = {
        'txt', 'rtf', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'svg',
        'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
        'zip', 'rar', '7z', 'tar', 'gz', 'tgz',
        'mp3', 'mp4', 'avi', 'mkv', 'mov', 'webm',
        'py', 'js', 'html', 'css', 'xml', 'mobileconfig', 'c', 'h',
        'cpp', 'cs', 'php', 'rb', 'go', 'ts', 'swift', 'sh', 'java',
        'db', 'sqlite', 'sqlite3', 'mdb', 'accdb', 'mdf', 'ldf',
        'frm', 'ibd', 'myd', 'myi', 'csv', 'tsv', 'json', 'bson',
        'parquet', 'md', 'yml', 'yaml', 'pbix', 'pbit', 'pbip',
        'twbx', 'twb', 'hyper', 'tds'
    }

    # mDNS
    MDNS_DOMAIN = 'portus.local'


# Load authentication PIN from environment
load_dotenv('secrets.env')
VALID_PIN = int(os.getenv('PIN', '0'))
_session_secret_key = secrets.token_hex(32)


# ------------------------------
# GLOBAL STATE MANAGEMENT
# ------------------------------

# Cleanup tracking
_cleanup_done = False
_cleanup_lock = threading.Lock()

# mDNS service registration state
_mdns_state = {
    'zeroconf': None,
    'service_info': None,
    'registered': False,
    'lock': threading.Lock()
}

# File uploads and Server-Sent Events (SSE)
_active_uploads: dict = {}
_active_uploads_lock = threading.Lock()

# Chunked/resumable uploads (server-side tracking)
_chunk_uploads: dict = {}
_chunk_uploads_lock = threading.Lock()

_sse_clients: set = set()
_sse_clients_lock = threading.Lock()
_server_shutting_down = False

# File tracking
_files_state = {
    'last_modified': time.time(),
    'files_hash': ''
}
_files_state_lock = threading.Lock()


# Ensure shared files folder and temp uploads folder exist in Portus_Dock
os.makedirs(Config.SHARED_FILES_FOLDER, exist_ok=True)
os.chmod(Config.SHARED_FILES_FOLDER, 0o755)
os.makedirs(Config.TEMP_UPLOADS_FOLDER, exist_ok=True)

import concurrent.futures as _cf
_thread_pool = _cf.ThreadPoolExecutor(max_workers=50, thread_name_prefix='portus')
_upload_semaphore: asyncio.Semaphore


# ------------------------------
# SSE UTILITIES
# ------------------------------

def send_sse_event(event: str, data: str = '') -> None:
    """Pushes an SSE event to all connected clients."""
    message = f"event: {event}\ndata: {data}\n\n"
    with _sse_clients_lock:
        for q in list(_sse_clients):
            try:
                q.put_nowait(message)
            except asyncio.QueueFull:
                pass
            except Exception:
                pass


# ------------------------------
# mDNS SERVICE MANAGEMENT
# ------------------------------

def _get_local_ip() -> Optional[str]:
    """Gets the system's local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
        s.close()
        if local_ip:
            return local_ip
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        return socket.gethostbyname(hostname)
    except Exception:
        return None


def register_mdns_service(port: int = Config.PORT, use_https: bool = True) -> None:
    """Registers the Portus service on the local network using mDNS (Python-Zeroconf)."""
    try:
        with _mdns_state['lock']:
            hostname = socket.gethostname() or 'portus'

            # Get local IP address
            addresses = []
            local_ip = _get_local_ip()
            if local_ip and local_ip != '127.0.0.1':
                try:
                    addresses.append(socket.inet_aton(local_ip))
                except Exception:
                    pass

            # Fallback to loopback
            if not addresses:
                addresses.append(socket.inet_aton('127.0.0.1'))

            # Register mDNS service
            service_type = '_https._tcp.local.' if use_https else '_http._tcp.local.'
            service_name = f"Portus.{service_type}"

            service_info = ServiceInfo(
                service_type,
                service_name,
                addresses=addresses,
                port=port,
                properties={
                    'path': '/',
                    'version': '1.0',
                },
                server=f"{Config.MDNS_DOMAIN}.",
            )

            _mdns_state['zeroconf'] = Zeroconf()
            _mdns_state['zeroconf'].register_service(service_info)
            _mdns_state['service_info'] = service_info
            _mdns_state['registered'] = True

            print(f"mDNS service registered at: https://{Config.MDNS_DOMAIN}:{port}")

    except Exception as e:
        print(f"\nmDNS registration warning: {e}")
        print(f"  Kindly ensure your network supports mDNS")
        _mdns_state['registered'] = False


def unregister_mdns_service() -> None:
    """Unregisters the Portus service from the local network."""
    try:
        with _mdns_state['lock']:
            if _mdns_state['registered'] and _mdns_state['zeroconf'] and _mdns_state['service_info']:
                try:
                    _mdns_state['zeroconf'].unregister_service(_mdns_state['service_info'])
                    _mdns_state['zeroconf'].close()
                    _mdns_state['registered'] = False
                    _mdns_state['service_info'] = None
                    _mdns_state['zeroconf'] = None
                    print("mDNS service unregistered.")
                except Exception as e:
                    print(f"Warning: Error unregistering mDNS service: {e}")
    except Exception as e:
        print(f"Warning: Error in unregister_mdns_service: {e}")


# ------------------------------
# FILE STATE TRACKING
# ------------------------------

def get_files_hash() -> str:
    """Generates a hash representing the current state of files."""
    try:
        files = sorted(os.listdir(Config.SHARED_FILES_FOLDER))
        files_info = []
        for filename in files:
            filepath = os.path.join(Config.SHARED_FILES_FOLDER, filename)
            if os.path.isfile(filepath):
                mtime = os.path.getmtime(filepath)
                size = os.path.getsize(filepath)
                files_info.append(f"{filename}:{mtime}:{size}")
        return hashlib.md5('|'.join(files_info).encode()).hexdigest()
    except Exception:
        return ''


def update_files_state() -> None:
    """Updates the files state tracking."""
    with _files_state_lock:
        _files_state['files_hash'] = get_files_hash()
        _files_state['last_modified'] = time.time()


# ------------------------------
# AUTHENTICATION & AUTHORIZATION
# ------------------------------

def auth_required(request: Request) -> dict:
    """
    FastAPI dependency to enforce auth and session timeout.
    Raises HTTP 401 if user is not authenticated or the session has expired.
    Returns the session dict on success.
    """
    session = request.session

    if not session.get('authenticated'):
        raise HTTPException(status_code=401, detail={'error': 'Authentication required'})

    last_activity = session.get('last_activity')
    if last_activity:
        last_activity_time = datetime.fromisoformat(last_activity)
        if datetime.now() - last_activity_time > timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES):
            session.clear()
            raise HTTPException(
                status_code=401,
                detail={'error': 'Session timeout', 'timeout': True}
            )

    session['last_activity'] = datetime.now().isoformat()
    return session


def auth_required_readonly(request: Request) -> dict:
    session = request.session

    if not session.get('authenticated'):
        raise HTTPException(status_code=401, detail={'error': 'Authentication required'})

    last_activity = session.get('last_activity')
    if last_activity:
        if datetime.now() - datetime.fromisoformat(last_activity) > timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES):
            session.clear()
            raise HTTPException(
                status_code=401,
                detail={'error': 'Session timeout', 'timeout': True}
            )

    return session


# ------------------------------
# FILE UTILITIES
# ------------------------------

def allowed_file(filename: Optional[str]) -> bool:
    """Checks if the file extension is allowed for the file being uploaded."""
    if not filename:
        return False
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def sanitize_filename(filename: Optional[str]) -> str:
    """Sanitizes filenames to prevent directory traversal attacks."""
    if filename is None:
        filename = ''
    filename = secure_filename(filename)
    filename = filename.replace('..', '')
    return filename


def validate_file_path(filepath: str) -> bool:
    """
    Validates that a file path is within the allowed directory.
    Returns True if valid, False otherwise.
    """
    if not os.path.exists(filepath) or not os.path.isfile(filepath):
        return False

    allowed_dir = os.path.abspath(Config.SHARED_FILES_FOLDER)
    file_path = os.path.abspath(filepath)
    return file_path.startswith(allowed_dir + os.sep) or file_path == allowed_dir


def save_file_with_hash(file_storage, filepath: str, upload_id: str):
    """
    Saves a file and calculates its SHA-256 hash simultaneously.
    Returns (hash, total_bytes) or (None, bytes_written) if cancelled.
    """
    sha256_hash = hashlib.sha256()
    total_bytes = 0

    try:
        with open(filepath, 'wb') as f:
            while True:
                # Check if upload was cancelled
                with _active_uploads_lock:
                    if upload_id in _active_uploads:
                        if _active_uploads[upload_id].get('cancelled'):
                            return None, total_bytes
                    else:
                        break

                chunk = file_storage.read(Config.UPLOAD_CHUNK_SIZE)
                if not chunk:
                    break

                sha256_hash.update(chunk)
                f.write(chunk)
                total_bytes += len(chunk)

                # Update progress
                with _active_uploads_lock:
                    if upload_id in _active_uploads:
                        _active_uploads[upload_id]['bytes_written'] = total_bytes

        return sha256_hash.hexdigest(), total_bytes
    except Exception as e:
        raise e


def cleanup_temp_uploads() -> None:
    """Removes any temporary upload artifacts from the '.uploads' folder inside the Portus_Dock."""
    # Close any open file handles first to avoid resource leaks
    with _chunk_uploads_lock:
        for info in _chunk_uploads.values():
            fh = info.get('file_handle')
            if fh:
                try:
                    fh.close()
                except Exception:
                    pass

    temp_dir = os.path.abspath(Config.TEMP_UPLOADS_FOLDER)
    try:
        if not os.path.isdir(temp_dir):
            return

        for name in os.listdir(temp_dir):
            full_path = os.path.join(temp_dir, name)
            try:
                if os.path.isfile(full_path) or os.path.islink(full_path):
                    os.remove(full_path)
                elif os.path.isdir(full_path):
                    shutil.rmtree(full_path, ignore_errors=True)
            except Exception:
                continue
    except Exception:
        pass


def init_chunk_upload(filename: str, total_size: int) -> str:
    """
    Initializes a resumable chunked upload and returns an upload_id.
    Keeps all temporary data inside Portus_Dock/.uploads and tracks a
    running SHA-256 hash without impacting upload throughput.
    """
    safe_name = sanitize_filename(filename)
    upload_id = uuid.uuid4().hex
    temp_path = os.path.join(Config.TEMP_UPLOADS_FOLDER, f"{upload_id}.part")

    # Ensure any previous artifacts with the same id are removed
    try:
        if os.path.exists(temp_path):
            os.remove(temp_path)
    except Exception:
        pass

    # Open the file handle once. Reused by every append_chunk call
    # to avoid ~340 open/close cycles for a 1 GB or larger file
    fh = open(temp_path, 'wb')

    with _chunk_uploads_lock:
        _chunk_uploads[upload_id] = {
            'filename': safe_name,
            'total_size': int(total_size),
            'temp_path': temp_path,
            'file_handle': fh,
            'sha256': hashlib.sha256(),
            'bytes_hashed': 0
        }

    return upload_id


def append_chunk(upload_id: str, offset: int, data: bytes):
    """
    Appends/overwrites a single chunk for a resumable upload.
    Returns (success: bool, result: str | dict).
    """
    with _chunk_uploads_lock:
        info = _chunk_uploads.get(upload_id)
        if not info:
            return False, 'Invalid upload_id'
        temp_path = info['temp_path']
        total_size = info['total_size']
        fh = info['file_handle']

    if offset < 0 or offset > total_size:
        return False, 'Invalid offset'

    try:
        fh.seek(offset)
        fh.write(data)
        fh.flush()
    except Exception as e:
        return False, str(e)

    # Determine if this chunk advances the hash frontier.
    # Reads bytes_hashed under the lock, but does the actual CPU-heavy
    # sha256.update() OUTSIDE the lock so other uploads aren't blocked.
    do_hash = False
    with _chunk_uploads_lock:
        info = _chunk_uploads.get(upload_id)
        if not info:
            return False, 'Invalid upload_id'
        if offset == info['bytes_hashed']:
            do_hash = True
        elif offset > info['bytes_hashed']:
            return False, 'Non-sequential chunk detected'
        sha = info['sha256']

    if do_hash:
          # CPU-heavy, runs outside the lock
        sha.update(data)
        with _chunk_uploads_lock:
            info = _chunk_uploads.get(upload_id)
            if info:
                info['bytes_hashed'] += len(data)

    with _chunk_uploads_lock:
        info = _chunk_uploads.get(upload_id)
        if not info:
            return False, 'Invalid upload_id'
        total = info['total_size']
        hashed = info['bytes_hashed']

    current_size = os.path.getsize(temp_path) if os.path.exists(temp_path) else 0
    return True, {
        'received': current_size,
        'total': total,
        'bytes_hashed': hashed
    }

def finalize_chunk_upload(upload_id: str):
    """
    Finalizes a chunked upload: moves the completed file into the main
    Portus_Dock and updates file state.
    Returns (success: bool, error: str | None, info: dict | None).
    """
    with _chunk_uploads_lock:
        info = _chunk_uploads.get(upload_id)
        if not info:
            return False, 'Invalid upload_id', None

        filename = info['filename']
        total_size = info['total_size']
        temp_path = info['temp_path']
        sha256 = info['sha256']
        bytes_hashed = info['bytes_hashed']
        fh = info.get('file_handle')

    if not os.path.exists(temp_path):
        return False, 'Temporary file missing', None

    current_size = os.path.getsize(temp_path)
    if current_size != total_size:
        return False, 'Upload incomplete', None
    if bytes_hashed != total_size:
        return False, 'Hash not fully computed', None

    # Close the persistent file handle before moving the file
    if fh:
        try:
            fh.close()
        except Exception:
            pass

    # Resolve final destination filename avoiding collisions
    base_filename = filename
    counter = 1
    dest_path = os.path.join(Config.SHARED_FILES_FOLDER, filename)
    while os.path.exists(dest_path):
        name, ext = os.path.splitext(base_filename)
        filename = f"{name}_{counter}{ext}"
        dest_path = os.path.join(Config.SHARED_FILES_FOLDER, filename)
        counter += 1

    try:
        shutil.move(temp_path, dest_path)
    except Exception as e:
        return False, str(e), None

    file_hash = sha256.hexdigest()

    with _chunk_uploads_lock:
        _chunk_uploads.pop(upload_id, None)

    return True, None, {
        'filename': filename,
        'size': total_size,
        'hash': file_hash,
        'path': dest_path
    }


# ------------------------------
# FIREWALL & CLEANUP MANAGEMENT
# ------------------------------

def open_firewall_port(port: int = Config.PORT) -> None:
    """Opens the firewall port for the application (platform-specific)."""
    system = platform.system()
    try:
        if system == 'Linux':
            subprocess.run(['sudo', 'ufw', 'allow', str(port)], check=False)
            print("Firewall port opened (Linux/UFW)")
            print("-" * 60 + "\n")
        elif system == 'Windows':
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name=Portus File Share',
                'dir=in', 'action=allow', 'protocol=TCP',
                f'localport={port}'
            ], check=False, capture_output=True)
            print("Firewall port opened (Windows)")
            print("-" * 60 + "\n")
            
        else:
            if system == 'Darwin':
                print("macOS: You may need to manually allow the connection in: "
                      "Apple menu > System Settings > Network > Firewall")
                print("-" * 60 + "\n")
            else:
                print(f"Unknown OS for Portus server: ({system})\nPlease manually configure firewall for port {port}")
                print("-" * 60 + "\n")
    except Exception as e:
        print(f"Could not automatically open firewall port: {e}")
        print(f"Please manually allow port {port} in your firewall settings")
        print("-" * 60 + "\n")


def close_firewall_port(port: int = Config.PORT) -> None:
    """Closes the firewall port and cleans up resources for proper server shutdown."""
    global _cleanup_done, _server_shutting_down
    _server_shutting_down = True

    with _cleanup_lock:
        if _cleanup_done:
            return
        _cleanup_done = True

    # Clean up all partial / in-progress chunked uploads in the directory
    try:
        cleanup_temp_uploads()
    except Exception:
        pass
    try:
        with _chunk_uploads_lock:
            _chunk_uploads.clear()
    except Exception:
        pass
    
    # Unregister mDNS service
    unregister_mdns_service()

    # Remove firewall rule (platform-specific)
    system = platform.system()
    try:
        if system == 'Linux':
            subprocess.run(
                ['sudo', 'ufw', 'delete', 'allow', str(port)],
                input='y\n', text=True, check=False
            )
            print("Firewall rule removed (Linux/UFW)")
            print("-" * 60 + "\n")
        elif system == 'Windows':
            subprocess.run([
                'netsh', 'advfirewall', 'firewall', 'delete', 'rule',
                'name=Portus File Share'
            ], check=False, capture_output=True)
            print("Firewall rule removed (Windows)")
            print("-" * 60 + "\n")
        else:
            if system == 'Darwin':
                print("macOS: Firewall rules persist.\nNo action needed.")
                print("Exiting the application.")
                print("-" * 60 + "\n")
            else:
                print("""Unknown OS for the Portus server: Firewall rules may persist.
                      \nPlease proceed accordingly after after server shut down.""")
                print("-" * 60 + "\n")
    except Exception as e:
        print(f"Could not close firewall port: {e}")
        print("-" * 60 + "\n")


# ------------------------------
# FASTAPI APPLICATION SETUP
# ------------------------------

_use_https: bool = (
    os.path.exists(Config.CERT_FILE) and
    os.path.exists(Config.KEY_FILE)
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manages application startup and shutdown lifecycle."""
    global _upload_semaphore, _server_shutting_down

    # Attach the expanded thread pool to the running event loop
    loop = asyncio.get_running_loop()
    loop.set_default_executor(_thread_pool)
    loop.set_exception_handler(_custom_asyncio_exception_handler)
    _upload_semaphore = asyncio.Semaphore(Config.MAX_CONCURRENT_UPLOADS)
    update_files_state()

    print("\n" + "-" * 60)
    print("Portus | Secure LAN File Sharing")
    print("-" * 60)
    
    use_https = _use_https
    protocol = "https" if use_https else "http"
    host_addr = f"{protocol}://{Config.MDNS_DOMAIN}:{Config.PORT}"

    if use_https:
        print("\nHTTPS mode enabled (SSL certificates found)")
    else:
        print("\nRunning in HTTP mode (no SSL certificates)")
        print("   To enable HTTPS: run 'python Portus_SSL_genny.py' first.")

    print("\nTO ACCESS FROM DEVICES ON YOUR NETWORK VISIT:")
    print(f"   {host_addr}")

    if not use_https:
        print("\niOS/HTTPS-ONLY BROWSERS error:")
        print("   If you get 'HTTPS-Only' errors on iOS:")
        print("     Please run 'python Portus_SSL_genny.py' to enable HTTPS")
    else:
        print("\niOS USERS NOTE:")
        print("   Your browser(s) will show a security warning for this self-signed certificate.")
        print("   Tap 'Show Details' → 'visit this website' to continue.")

    print(f"\nCLIENT SESSION TIMES OUT AFTER: {Config.SESSION_TIMEOUT_MINUTES} minutes of inactivity")
    

    register_mdns_service(port=Config.PORT, use_https=use_https)
    open_firewall_port()

    try:
        yield
    finally:
        # _PortusServer.shutdown() already handles this in the normal path.
        # This finally block is a fallback for any edge-case direct cancellation.
        if not _server_shutting_down:
            _server_shutting_down = True
            send_sse_event(
                'shutdown',
                'Server shutting down. Please log in again when it restarts.'
            )
            try:
                await asyncio.shield(asyncio.sleep(0.5))
            except (asyncio.CancelledError, Exception):
                pass
        close_firewall_port()


app = FastAPI(title="Portus", lifespan=lifespan)


class _ShutdownGuard:
    """Pure ASGI middleware"""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and _server_shutting_down:
            # Drain the full request body so the client-side send completes cleanly
            while True:
                message = await receive()
                if message["type"] == "http.request" and not message.get("more_body", False):
                    break
            await send({
                "type": "http.response.start",
                "status": 503,
                "headers": [
                    (b"content-length", b"0"),
                    (b"x-shutdown-reason", b"Server is shutting down"),
                ],
            })
            await send({"type": "http.response.body", "body": b"", "more_body": False})
            return
        await self.app(scope, receive, send)

app.add_middleware(_ShutdownGuard)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    
    if isinstance(exc.detail, dict):
        return JSONResponse(exc.detail, status_code=exc.status_code)
    return JSONResponse({'error': str(exc.detail)}, status_code=exc.status_code)


app.add_middleware(
    SessionMiddleware,
    secret_key=_session_secret_key,
    max_age=int(Config.PERMANENT_SESSION_LIFETIME.total_seconds()),
    https_only=_use_https,
    same_site='lax'
)


# ------------------------------
# ROUTES - STATIC & BASIC
# ------------------------------

@app.get('/')
async def index():
    """Serves the main HTML page from the templates folder."""
    path = os.path.join('templates', 'Portus.html')
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            content = f.read()
        return Response(content=content, media_type='text/html')
    
    raise HTTPException(status_code=404, detail='Portus.html not found')


# ------------------------------
# ROUTES - SERVER-SENT EVENTS (SSE)
# ------------------------------

@app.get('/events')
async def sse_stream():
    """SSE stream endpoint for real-time server notifications to clients."""

    async def event_generator() -> AsyncGenerator[str, None]:
        q: asyncio.Queue = asyncio.Queue()

        with _sse_clients_lock:
            _sse_clients.add(q)

        try:
            yield 'event: connected\ndata: Connected to server\n\n'
            yield 'retry: 5000\n\n'

            while True:
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=10.0)
                except asyncio.TimeoutError:
                    if _server_shutting_down:
                        break
                    # Send a keep-alive comment so the connection stays open
                    yield ': keep-alive\n\n'
                    continue

                # Shutdown signal
                if msg is None:
                    break

                yield str(msg)

        except asyncio.CancelledError:
            pass
        finally:
            with _sse_clients_lock:
                _sse_clients.discard(q)

    return StreamingResponse(
        event_generator(),
        media_type='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )


# ------------------------------
# ROUTES - AUTHENTICATION & SESSION
# ------------------------------

@app.post('/auth')
async def authenticate(request: Request):
    """Authenticates user with PIN."""
    try:
        data = await request.json()
        pin = int(data.get('pin', ''))

        if pin == VALID_PIN:
            request.session['authenticated'] = True
            request.session['last_activity'] = datetime.now().isoformat()
            return JSONResponse({'success': True}, status_code=200)
        else:
            return JSONResponse({'success': False, 'error': 'Invalid PIN'}, status_code=401)
    except (ValueError, TypeError):
        return JSONResponse({'success': False, 'error': 'Invalid PIN'}, status_code=401)


@app.get('/check-auth')
async def check_auth_status(request: Request):
    """Checks if the user is currently authenticated."""
    session = request.session
    authenticated = session.get('authenticated', False)

    if authenticated:
        last_activity = session.get('last_activity')
        if last_activity:
            elapsed = datetime.now() - datetime.fromisoformat(last_activity)
            if elapsed > timedelta(minutes=Config.SESSION_TIMEOUT_MINUTES):
                session.clear()
                authenticated = False

    return JSONResponse({'authenticated': authenticated}, status_code=200)


@app.post('/logout')
async def logout(request: Request):
    """Logs out the current user."""
    request.session.clear()
    return JSONResponse({'success': True, 'message': 'Logged out successfully'}, status_code=200)


@app.post('/register-activity')
async def register_activity(
    request: Request,
    session: dict = Depends(auth_required)
):
    """Registers user activity to reset the session timeout counter."""
    request.session['last_activity'] = datetime.now().isoformat()
    return JSONResponse({'success': True}, status_code=200)


# ------------------------------
# ROUTES - FILE TRACKING & NOTIFICATIONS
# ------------------------------

@app.get('/check-changes')
async def check_changes(session: dict = Depends(auth_required)):
    """Checks if files have changed since the last refresh."""
    with _files_state_lock:
        # current_hash = get_files_hash()
        return JSONResponse({
            # 'files_hash': current_hash,
            'files_hash': _files_state['files_hash'],
            'last_modified': _files_state['last_modified']
        }, status_code=200)


@app.post('/notify-change')
async def notify_change(session: dict = Depends(auth_required)):
    """Notifies the server that file changes have occurred."""
    await asyncio.to_thread(update_files_state)
    return JSONResponse({'success': True}, status_code=200)


# ------------------------------
# ROUTES - FILE OPERATIONS
# ------------------------------

@app.post('/upload')
async def upload_files(
    request: Request,
    file: List[UploadFile] = File(...),
    session: dict = Depends(auth_required)
):
    """Handles single or multiple file uploads."""
    if not file or all(f.filename == '' for f in file):
        return JSONResponse({'error': 'No file selected'}, status_code=400)

    uploaded_files = []
    errors = []

    async with _upload_semaphore:
        for f in file:
            if f.filename == '':
                continue

            if not allowed_file(f.filename):
                errors.append({'filename': f.filename, 'error': 'File type not supported!'})
                continue

            # Sanitize and handle filename duplicates
            filename = sanitize_filename(f.filename)
            base_filename = filename
            counter = 1
            while os.path.exists(os.path.join(Config.SHARED_FILES_FOLDER, filename)):
                name, ext = os.path.splitext(base_filename)
                filename = f"{name}_{counter}{ext}"
                counter += 1

            filepath = os.path.join(Config.SHARED_FILES_FOLDER, filename)
            upload_id = f"{filename}-{time.time()}"

            try:
                with _active_uploads_lock:
                    _active_uploads[upload_id] = {
                        'filename': filename,
                        'start_time': time.time(),
                        'bytes_written': 0,
                        'cancelled': False
                    }

                file_hash, total_bytes = await asyncio.to_thread(
                    save_file_with_hash, f.file, filepath, upload_id
                )

                with _active_uploads_lock:
                    _active_uploads.pop(upload_id, None)

                if file_hash is None:
                    if os.path.exists(filepath):
                        os.remove(filepath)
                    errors.append({'filename': f.filename, 'error': 'Upload cancelled'})
                    continue

                uploaded_files.append({
                    'filename': filename,
                    'original_filename': f.filename,
                    'size': total_bytes,
                    'hash': file_hash
                })

            except Exception as e:
                with _active_uploads_lock:
                    _active_uploads.pop(upload_id, None)

                if os.path.exists(filepath):
                    try:
                        os.remove(filepath)
                    except Exception:
                        pass

                errors.append({'filename': f.filename, 'error': str(e)})

    if uploaded_files:
        await asyncio.to_thread(update_files_state)
        await asyncio.to_thread(cleanup_temp_uploads)

    response_body = {
        'uploaded': uploaded_files,
        'message': 'No files uploaded' if not uploaded_files
                   else f'{len(uploaded_files)} file(s) uploaded successfully.'
    }
    if errors:
        response_body['errors'] = errors

    return JSONResponse(response_body, status_code=200)


@app.post('/upload-init')
async def upload_init(request: Request, session: dict = Depends(auth_required)):
    """
    Initializes a resumable chunked upload for a single file.
    Returns an upload_id that the client uses for subsequent chunks.
    """
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({'error': 'Invalid JSON'}, status_code=400)

    filename = (data or {}).get('filename', '')
    total_size = (data or {}).get('size', 0)

    if not filename:
        return JSONResponse({'error': 'Filename is required'}, status_code=400)
    try:
        total_size = int(total_size)
    except (TypeError, ValueError):
        return JSONResponse({'error': 'Invalid size'}, status_code=400)
    if total_size <= 0:
        return JSONResponse({'error': 'Invalid size'}, status_code=400)
    if not allowed_file(filename):
        return JSONResponse({'error': 'File type not allowed!'}, status_code=400)

    upload_id = init_chunk_upload(filename, total_size)
    return JSONResponse({'upload_id': upload_id}, status_code=200)


@app.post('/upload-chunk')
async def upload_chunk_route(
    request: Request,
    upload_id: str = Query(...),
    offset: int = Query(...),
    session: dict = Depends(auth_required_readonly)
):
    """
    Receives a single binary chunk for a previously initialized upload.
    The client sends upload_id and byte offset as query parameters.
    """
    if not upload_id:
        return JSONResponse({'error': 'upload_id is required'}, status_code=400)

    try:
        chunk_data = await request.body()
    except Exception as e:
        return JSONResponse({'error': str(e)}, status_code=400)

    if not chunk_data:
        return JSONResponse({'error': 'Empty chunk'}, status_code=400)

    ok, result = await asyncio.to_thread(append_chunk, upload_id, offset, chunk_data)
    if not ok:
        return JSONResponse({'error': result}, status_code=400)

    return JSONResponse(result, status_code=200)

@app.post('/upload-complete')
async def upload_complete(request: Request, session: dict = Depends(auth_required)):
    """
    Finalizes a resumable upload: moves the completed file into the main
    Portus_Dock and updates file state.
    """
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({'error': 'Invalid JSON'}, status_code=400)

    upload_id = (data or {}).get('upload_id', '').strip()
    if not upload_id:
        return JSONResponse({'error': 'upload_id is required'}, status_code=400)

    ok, err, info = await asyncio.to_thread(finalize_chunk_upload, upload_id)
    if not ok or info is None:
        return JSONResponse({'error': (err or 'Finalization failed')}, status_code=400)

    await asyncio.to_thread(update_files_state)
    await asyncio.to_thread(cleanup_temp_uploads)

    return JSONResponse({
        'uploaded': [{
            'filename': info['filename'],
            'original_filename': info['filename'],
            'size': info['size'],
            'hash': info['hash']
        }],
        'message': 'File uploaded successfully (chunked)'
    }, status_code=200)


@app.post('/cancel-upload')
async def cancel_upload(request: Request, session: dict = Depends(auth_required)):
    """Cancels an active upload."""
    try:
        data = await request.json()
        filename = data.get('filename', '')

        if not filename:
            return JSONResponse({'error': 'No filename provided'}, status_code=400)

        cancelled = False
        with _active_uploads_lock:
            for upload_id, info in _active_uploads.items():
                if info['filename'] == filename:
                    info['cancelled'] = True
                    cancelled = True

        if cancelled:
            return JSONResponse({'success': True, 'message': 'Upload cancelled'}, status_code=200)
        else:
            return JSONResponse({'error': 'Upload not found or already completed'}, status_code=404)
    except Exception as e:
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/files')
async def list_files(session: dict = Depends(auth_required)):
    """Lists all files in the Portus_Dock directory with metadata."""
    files = []
    try:
        for filename in os.listdir(Config.SHARED_FILES_FOLDER):
            filepath = os.path.join(Config.SHARED_FILES_FOLDER, filename)
            if os.path.isfile(filepath):
                mimetype, _ = mimetypes.guess_type(filepath)
                files.append({
                    'name': filename,
                    'size': os.path.getsize(filepath),
                    'modified': datetime.fromtimestamp(
                        os.path.getmtime(filepath)
                    ).strftime('%Y-%m-%d %H:%M:%S'),
                    'type': mimetype or 'application/octet-stream'
                })
    except Exception as e:
        return JSONResponse({'error': str(e)}, status_code=500)

    # Sort by modified date with newest file first
    files.sort(key=lambda x: x['modified'], reverse=True)
    return JSONResponse(files)


@app.get('/view/{filename}')
async def view_file(filename: str, request: Request, session: dict = Depends(auth_required)):
    """Serves a file for inline viewing / video streaming in the browser."""
    filename = sanitize_filename(filename)
    filepath = os.path.join(Config.SHARED_FILES_FOLDER, filename)

    if not validate_file_path(filepath):
        raise HTTPException(status_code=404)

    file_size = os.path.getsize(filepath)
    mimetype, _ = mimetypes.guess_type(filepath)
    media_type = mimetype or 'application/octet-stream'
    range_header = request.headers.get('Range')

    if not range_header:
        async def generate_full():
            async with aiofiles.open(filepath, 'rb') as f:
                while not _server_shutting_down:
                    chunk = await f.read(Config.DOWNLOAD_CHUNK_SIZE)
                    if not chunk:
                        break
                    yield chunk
                    await asyncio.sleep(0.003)

        return StreamingResponse(
            generate_full(),
            status_code=200,
            media_type=media_type,
            headers={
                'Accept-Ranges': 'bytes',
                'Content-Length': str(file_size),
                'Content-Disposition': f'inline; filename="{filename}"',
            }
        )

    m = re.match(r'bytes=(\d+)-(\d*)', range_header)
    if not m:
        return Response(content='Invalid Range header', status_code=416)

    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else file_size - 1

    if start >= file_size or end >= file_size or start > end:
        return Response(
            content='Requested Range Not Satisfiable',
            status_code=416,
            headers={'Content-Range': f'bytes */{file_size}'}
        )

    length = end - start + 1

    if length <= 10240:
        async with aiofiles.open(filepath, 'rb') as f:
            await f.seek(start)
            probe_data = await f.read(length)
        return Response(
            content=probe_data,
            status_code=206,
            media_type=media_type,
            headers={
                'Content-Range': f'bytes {start}-{end}/{file_size}',
                'Accept-Ranges': 'bytes',
                'Content-Length': str(length),
                'Content-Disposition': f'inline; filename="{filename}"',
            }
        )

    async def generate_range():
        async with aiofiles.open(filepath, 'rb') as f:
            await f.seek(start)
            remaining = length
            while remaining > 0:
                if _server_shutting_down:
                    raise asyncio.CancelledError()
                chunk = await f.read(min(Config.DOWNLOAD_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk
                await asyncio.sleep(0.003)

    return StreamingResponse(
        generate_range(),
        status_code=206,
        media_type=media_type,
        headers={
            'Content-Range': f'bytes {start}-{end}/{file_size}',
            'Accept-Ranges': 'bytes',
            'Content-Length': str(length),
            'Content-Disposition': f'inline; filename="{filename}"',
            'Cache-Control': 'no-store',
        }
    )


@app.get('/files/{filename}')
async def download_file(
    filename: str,
    request: Request,
    session: dict = Depends(auth_required)
):
    """Downloads a file from the Portus_Dock with HTTP range request support."""
    filename = sanitize_filename(filename)
    filepath = os.path.join(Config.SHARED_FILES_FOLDER, filename)

    if not validate_file_path(filepath):
        raise HTTPException(status_code=404)

    file_size = os.path.getsize(filepath)
    range_header = request.headers.get('Range')

    if not range_header:
        async def generate_full():
            async with aiofiles.open(filepath, 'rb') as f:
                while True:
                    if _server_shutting_down:
                        raise asyncio.CancelledError()
                    chunk = await f.read(Config.DOWNLOAD_CHUNK_SIZE)
                    if not chunk:
                        break
                    yield chunk
                    await asyncio.sleep(0.003)

        return StreamingResponse(
            generate_full(),
            status_code=200,
            media_type='application/octet-stream',
            headers={
                'Accept-Ranges': 'bytes',
                'Content-Length': str(file_size),
                'Content-Disposition': f'attachment; filename="{filename}"',
            }
        )

    m = re.match(r'bytes=(\d+)-(\d*)', range_header)
    if not m:
        return Response(content='Invalid Range header', status_code=416)

    start = int(m.group(1))
    end = int(m.group(2)) if m.group(2) else file_size - 1

    if start >= file_size or end >= file_size or start > end:
        return Response(content='Requested Range Not Satisfiable', status_code=416)

    length = end - start + 1

    async def generate():
        async with aiofiles.open(filepath, 'rb') as f:
            await f.seek(start)
            remaining = length
            while remaining > 0:
                if _server_shutting_down:
                    raise asyncio.CancelledError()
                chunk = await f.read(min(Config.DOWNLOAD_CHUNK_SIZE, remaining))
                if not chunk:
                    break
                remaining -= len(chunk)
                yield chunk
                await asyncio.sleep(0.003)

    return StreamingResponse(
        generate(),
        status_code=206,
        media_type='application/octet-stream',
        headers={
            'Content-Range': f'bytes {start}-{end}/{file_size}',
            'Accept-Ranges': 'bytes',
            'Content-Length': str(length),
            'Content-Disposition': f'attachment; filename="{filename}"'
        }
    )


@app.delete('/files/{filename}')
async def delete_file(filename: str, session: dict = Depends(auth_required)):
    """Deletes a file from the Portus_Dock."""
    filename = sanitize_filename(filename)
    filepath = os.path.join(Config.SHARED_FILES_FOLDER, filename)

    if not validate_file_path(filepath):
        return JSONResponse({'error': 'File not found'}, status_code=404)

    try:
        os.remove(filepath)
        await asyncio.to_thread(update_files_state)
        return JSONResponse({
            'success': True,
            'message': f'{filename} deleted successfully'
        }, status_code=200)
    except Exception as e:
        return JSONResponse({'error': str(e)}, status_code=500)


@app.get('/health')
async def health():
    """Simple health check endpoint used by clients to distinguish transient network issues."""
    return JSONResponse({'status': 'ok'}, status_code=200)


# ------------------------------
# ROUTES - THEME PREFERENCES
# ------------------------------

@app.api_route('/theme', methods=['GET', 'POST'])
async def theme(request: Request):
    """
    Handles theme preference.
    Default theme: dark.
    """
    if request.method == 'POST':
        data = await request.json()
        selected_theme = data.get('theme', 'dark')
        request.session['theme'] = selected_theme
        return JSONResponse({'success': True, 'theme': selected_theme}, status_code=200)
    else:
        return JSONResponse({'theme': request.session.get('theme', 'dark')}, status_code=200)


class _PortusServer(uvicorn.Server):
    """Uvicorn Server subclass that sets the shutdown flag and notifies all
    SSE clients the moment uvicorn begins draining connections — before any
    existing connection is closed.
    """

    async def shutdown(self, sockets=None):
        global _server_shutting_down
        if not _server_shutting_down:
            _server_shutting_down = True
            send_sse_event(
                'shutdown',
                'Server shutting down. Please log in again when it restarts.'
            )
            # Give the event loop one pass to dispatch the queued SSE message
            # to the generator coroutines before uvicorn starts closing sockets.
            await asyncio.sleep(0.5)
        await super().shutdown(sockets=sockets)


# ------------------------------
# APPLICATION ENTRY POINT
# ------------------------------

if __name__ == '__main__':
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    use_https = (
        os.path.exists(Config.CERT_FILE) and
        os.path.exists(Config.KEY_FILE)
    )

    ssl_kwargs: dict = {}
    if use_https:
        ssl_kwargs['ssl_certfile'] = Config.CERT_FILE
        ssl_kwargs['ssl_keyfile'] = Config.KEY_FILE

    uvicorn_config = uvicorn.Config(
        app,
        host=Config.HOST,
        port=Config.PORT,
        loop='asyncio',
        backlog=512,
        timeout_keep_alive=120,
        timeout_graceful_shutdown=8,
        limit_concurrency=200,
        h11_max_incomplete_event_size=65536,
        **ssl_kwargs
    )

    server = _PortusServer(uvicorn_config)

    async def _serve():
        loop = asyncio.get_running_loop()
        loop.set_exception_handler(_custom_asyncio_exception_handler)
        await server.serve()

    try:
        asyncio.run(_serve())
    except KeyboardInterrupt:
        print("\nShut down completed.")
        print("-" * 60 + "\n")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        close_firewall_port()
