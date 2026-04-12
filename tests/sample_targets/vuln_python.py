# BAYREUTHWING — Test Sample Targets

# This file contains intentionally vulnerable Python code
# for testing the BAYREUTHWING scanner.

import os
import pickle
import hashlib
import random
import subprocess

# ── VULN: Hardcoded Credentials (CWE-798) ──────────────
DATABASE_URL = "postgresql://admin:P@ssw0rd123@db.prod.internal:5432/app"
SECRET_KEY = "my-super-secret-key-do-not-share-ever"
AWS_ACCESS_KEY = "AKIA__PLACEHOLDER__DONT__USE"

# ── VULN: SQL Injection (CWE-89) ───────────────────────
def get_user_by_name(name):
    query = f"SELECT * FROM users WHERE username = '{name}'"
    cursor.execute(query)
    return cursor.fetchone()

def search_products(category, price):
    sql = "SELECT * FROM products WHERE category = '%s' AND price < %s" % (category, price)
    db.execute(sql)
    return db.fetchall()

# ── VULN: Command Injection (CWE-78) ───────────────────
def ping_server(host):
    os.system("ping -c 4 " + host)

def list_directory(path):
    result = subprocess.check_output("ls -la " + path, shell=True)
    return result.decode()

# ── VULN: Insecure Deserialization (CWE-502) ───────────
def load_user_data(raw_bytes):
    return pickle.loads(raw_bytes)

# ── VULN: Weak Cryptography (CWE-327) ──────────────────
def hash_user_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def verify_password(password, stored_hash):
    return hashlib.sha1(password.encode()).hexdigest() == stored_hash

# ── VULN: Insecure Randomness (CWE-330) ────────────────
def generate_session_token():
    return ''.join(random.choice('abcdef0123456789') for _ in range(32))

def generate_reset_code():
    return str(random.randint(100000, 999999))

# ── VULN: Path Traversal (CWE-22) ──────────────────────
def download_file(filename):
    filepath = os.path.join("/var/uploads", filename)
    with open(filepath, "rb") as f:
        return f.read()

# ── VULN: Sensitive Data Exposure (CWE-200) ────────────
def handle_error(error):
    import traceback
    return {
        "error": str(error),
        "traceback": traceback.format_exc(),
        "config": {
            "db_url": DATABASE_URL,
            "secret": SECRET_KEY,
        }
    }
