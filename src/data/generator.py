"""
BAYREUTHWING — Synthetic Vulnerability Data Generator

Generates labeled code samples for training the CodeTransformer model.
Each sample is a code snippet labeled with one or more vulnerability classes.
For each vulnerable sample, a corresponding safe (patched) version is also
generated to help the model learn the distinction.

The generator creates realistic code patterns across multiple languages,
covering all 11 vulnerability classes defined in the model configuration.
"""

import random
from typing import Optional


class SyntheticDataGenerator:
    """
    Generates synthetic vulnerable and safe code samples for model training.
    
    Each generated sample contains:
    - code: The source code string
    - labels: List of vulnerability class IDs (multi-label)
    - language: The programming language
    - is_vulnerable: Whether the code contains a vulnerability
    - vulnerability_name: Human-readable vulnerability name
    - description: Brief description of why it's vulnerable/safe
    """

    VULN_CLASSES = {
        0: "SQL Injection",
        1: "Cross-Site Scripting (XSS)",
        2: "Command Injection",
        3: "Path Traversal",
        4: "Hardcoded Credentials",
        5: "Insecure Deserialization",
        6: "Weak Cryptography",
        7: "Buffer Overflow",
        8: "Server-Side Request Forgery",
        9: "Sensitive Data Exposure",
        10: "Insecure Randomness",
    }

    def __init__(self, seed: Optional[int] = 42):
        """
        Args:
            seed: Random seed for reproducibility.
        """
        if seed is not None:
            random.seed(seed)

        # Build sample templates for each vulnerability class
        self._templates = self._build_templates()

    def generate(self, num_samples: int = 5000) -> list[dict]:
        """
        Generate a balanced dataset of vulnerable and safe code samples.
        
        Args:
            num_samples: Total number of samples to generate.
            
        Returns:
            List of sample dictionaries.
        """
        samples = []
        samples_per_class = num_samples // (len(self.VULN_CLASSES) * 2)  # *2 for vuln + safe

        for vuln_id in self.VULN_CLASSES:
            templates = self._templates[vuln_id]

            for _ in range(samples_per_class):
                template = random.choice(templates)

                # Generate vulnerable version
                vuln_sample = self._generate_variant(template, is_vulnerable=True)
                vuln_sample["labels"] = [vuln_id]
                vuln_sample["vulnerability_name"] = self.VULN_CLASSES[vuln_id]
                samples.append(vuln_sample)

                # Generate safe version
                safe_sample = self._generate_variant(template, is_vulnerable=False)
                safe_sample["labels"] = []
                safe_sample["vulnerability_name"] = "Safe"
                samples.append(safe_sample)

        # Shuffle
        random.shuffle(samples)
        return samples

    def _generate_variant(self, template: dict, is_vulnerable: bool) -> dict:
        """Generate a code variant with random variable/function name substitution."""
        if is_vulnerable:
            code = template["vulnerable"]
            description = template["vuln_description"]
        else:
            code = template["safe"]
            description = template["safe_description"]

        # Randomize variable names for diversity
        var_names = random.choice([
            {"var": "data", "func": "process", "param": "user_input", "result": "result"},
            {"var": "value", "func": "handle", "param": "request_data", "result": "output"},
            {"var": "payload", "func": "execute", "param": "raw_input", "result": "response"},
            {"var": "content", "func": "parse", "param": "form_data", "result": "parsed"},
            {"var": "info", "func": "validate", "param": "query_param", "result": "validated"},
        ])

        for key, val in var_names.items():
            code = code.replace(f"{{{key}}}", val)

        return {
            "code": code,
            "is_vulnerable": is_vulnerable,
            "language": template["language"],
            "description": description,
        }

    def _build_templates(self) -> dict[int, list[dict]]:
        """Build code templates for all vulnerability classes."""
        templates = {}

        # ── 0: SQL Injection ────────────────────────────────────────
        templates[0] = [
            {
                "language": "python",
                "vulnerable": '''def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()''',
                "safe": '''def get_user(username):
    query = "SELECT * FROM users WHERE name = %s"
    cursor.execute(query, (username,))
    return cursor.fetchone()''',
                "vuln_description": "String concatenation in SQL query allows injection",
                "safe_description": "Parameterized query prevents SQL injection",
            },
            {
                "language": "python",
                "vulnerable": '''def search_products(category):
    sql = f"SELECT * FROM products WHERE category = '{category}'"
    db.execute(sql)
    return db.fetchall()''',
                "safe": '''def search_products(category):
    sql = "SELECT * FROM products WHERE category = ?"
    db.execute(sql, [category])
    return db.fetchall()''',
                "vuln_description": "f-string in SQL query enables injection",
                "safe_description": "Placeholder parameter prevents injection",
            },
            {
                "language": "javascript",
                "vulnerable": '''app.get("/users", (req, res) => {
    const name = req.query.name;
    const query = "SELECT * FROM users WHERE name = '" + name + "'";
    db.query(query, (err, results) => {
        res.json(results);
    });
});''',
                "safe": '''app.get("/users", (req, res) => {
    const name = req.query.name;
    const query = "SELECT * FROM users WHERE name = ?";
    db.query(query, [name], (err, results) => {
        res.json(results);
    });
});''',
                "vuln_description": "Unsanitized user input concatenated into SQL",
                "safe_description": "Prepared statement with parameter binding",
            },
            {
                "language": "java",
                "vulnerable": '''public User findUser(String username) {
    String query = "SELECT * FROM users WHERE name = '" + username + "'";
    Statement stmt = connection.createStatement();
    ResultSet rs = stmt.executeQuery(query);
    return mapUser(rs);
}''',
                "safe": '''public User findUser(String username) {
    String query = "SELECT * FROM users WHERE name = ?";
    PreparedStatement pstmt = connection.prepareStatement(query);
    pstmt.setString(1, username);
    ResultSet rs = pstmt.executeQuery();
    return mapUser(rs);
}''',
                "vuln_description": "Statement with concatenated user input",
                "safe_description": "PreparedStatement with parameter binding",
            },
            {
                "language": "php",
                "vulnerable": '''function getUser($username) {
    $query = "SELECT * FROM users WHERE username = '$username'";
    $result = mysqli_query($conn, $query);
    return mysqli_fetch_assoc($result);
}''',
                "safe": '''function getUser($username) {
    $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}''',
                "vuln_description": "Direct variable interpolation in SQL query",
                "safe_description": "Prepared statement with bound parameters",
            },
            {
                "language": "python",
                "vulnerable": '''def delete_user(user_id):
    query = "DELETE FROM users WHERE id = %s" % user_id
    cursor.execute(query)
    db.commit()''',
                "safe": '''def delete_user(user_id):
    query = "DELETE FROM users WHERE id = %s"
    cursor.execute(query, (int(user_id),))
    db.commit()''',
                "vuln_description": "String formatting operator used in SQL query",
                "safe_description": "Parameterized query with type casting",
            },
            {
                "language": "go",
                "vulnerable": '''func GetUser(db *sql.DB, name string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", name)
    row := db.QueryRow(query)
    var user User
    err := row.Scan(&user.ID, &user.Name)
    return &user, err
}''',
                "safe": '''func GetUser(db *sql.DB, name string) (*User, error) {
    query := "SELECT * FROM users WHERE name = $1"
    row := db.QueryRow(query, name)
    var user User
    err := row.Scan(&user.ID, &user.Name)
    return &user, err
}''',
                "vuln_description": "Sprintf used to build SQL query with user input",
                "safe_description": "Parameterized query with placeholder",
            },
        ]

        # ── 1: Cross-Site Scripting (XSS) ──────────────────────────
        templates[1] = [
            {
                "language": "javascript",
                "vulnerable": '''app.get("/profile", (req, res) => {
    const name = req.query.name;
    res.send("<h1>Welcome " + name + "</h1>");
});''',
                "safe": '''const escapeHtml = require("escape-html");
app.get("/profile", (req, res) => {
    const name = escapeHtml(req.query.name);
    res.send("<h1>Welcome " + name + "</h1>");
});''',
                "vuln_description": "User input directly rendered in HTML response",
                "safe_description": "HTML escaping prevents XSS",
            },
            {
                "language": "javascript",
                "vulnerable": '''function displayComment(comment) {
    document.getElementById("comments").innerHTML += comment;
}''',
                "safe": '''function displayComment(comment) {
    const div = document.createElement("div");
    div.textContent = comment;
    document.getElementById("comments").appendChild(div);
}''',
                "vuln_description": "innerHTML with unsanitized content enables XSS",
                "safe_description": "textContent safely renders as text, not HTML",
            },
            {
                "language": "python",
                "vulnerable": '''@app.route("/search")
def search():
    query = request.args.get("q", "")
    return f"<h2>Results for: {query}</h2>"''',
                "safe": '''from markupsafe import escape

@app.route("/search")
def search():
    query = escape(request.args.get("q", ""))
    return f"<h2>Results for: {query}</h2>"''',
                "vuln_description": "User query reflected in HTML without escaping",
                "safe_description": "markupsafe.escape prevents XSS",
            },
            {
                "language": "java",
                "vulnerable": '''@GetMapping("/greet")
public String greet(@RequestParam String name) {
    return "<html><body><h1>Hello " + name + "</h1></body></html>";
}''',
                "safe": '''@GetMapping("/greet")
public String greet(@RequestParam String name, Model model) {
    model.addAttribute("name", HtmlUtils.htmlEscape(name));
    return "greet";
}''',
                "vuln_description": "User input reflected in HTML without encoding",
                "safe_description": "HtmlUtils.htmlEscape sanitizes user input",
            },
            {
                "language": "php",
                "vulnerable": '''<?php
    $search = $_GET["search"];
    echo "<p>You searched for: $search</p>";
?>''',
                "safe": '''<?php
    $search = htmlspecialchars($_GET["search"], ENT_QUOTES, "UTF-8");
    echo "<p>You searched for: $search</p>";
?>''',
                "vuln_description": "Direct output of GET parameter in HTML",
                "safe_description": "htmlspecialchars encodes special characters",
            },
        ]

        # ── 2: Command Injection ────────────────────────────────────
        templates[2] = [
            {
                "language": "python",
                "vulnerable": '''import os
def ping_host(hostname):
    os.system("ping -c 4 " + hostname)''',
                "safe": '''import subprocess
def ping_host(hostname):
    subprocess.run(["ping", "-c", "4", hostname], check=True)''',
                "vuln_description": "os.system with user-controlled input enables command injection",
                "safe_description": "subprocess.run with argument list prevents injection",
            },
            {
                "language": "python",
                "vulnerable": '''import subprocess
def list_files(directory):
    output = subprocess.check_output("ls -la " + directory, shell=True)
    return output.decode()''',
                "safe": '''import subprocess
def list_files(directory):
    output = subprocess.check_output(["ls", "-la", directory])
    return output.decode()''',
                "vuln_description": "shell=True with string concatenation allows injection",
                "safe_description": "Argument list without shell=True prevents injection",
            },
            {
                "language": "javascript",
                "vulnerable": '''const { exec } = require("child_process");
app.get("/lookup", (req, res) => {
    exec("nslookup " + req.query.host, (err, stdout) => {
        res.send(stdout);
    });
});''',
                "safe": '''const { execFile } = require("child_process");
app.get("/lookup", (req, res) => {
    execFile("nslookup", [req.query.host], (err, stdout) => {
        res.send(stdout);
    });
});''',
                "vuln_description": "exec with concatenated user input",
                "safe_description": "execFile with argument array prevents injection",
            },
            {
                "language": "php",
                "vulnerable": '''function checkDomain($domain) {
    $output = shell_exec("whois " . $domain);
    return $output;
}''',
                "safe": '''function checkDomain($domain) {
    $domain = escapeshellarg($domain);
    $output = shell_exec("whois " . $domain);
    return $output;
}''',
                "vuln_description": "shell_exec with unsanitized user input",
                "safe_description": "escapeshellarg sanitizes the input",
            },
            {
                "language": "ruby",
                "vulnerable": '''def check_dns(hostname)
    result = `dig #{hostname}`
    return result
end''',
                "safe": '''require "open3"
def check_dns(hostname)
    stdout, stderr, status = Open3.capture3("dig", hostname)
    return stdout
end''',
                "vuln_description": "Backtick execution with interpolated user input",
                "safe_description": "Open3.capture3 with separate arguments prevents injection",
            },
        ]

        # ── 3: Path Traversal ──────────────────────────────────────
        templates[3] = [
            {
                "language": "python",
                "vulnerable": '''@app.route("/download")
def download_file():
    filename = request.args.get("file")
    return send_file(os.path.join("/uploads", filename))''',
                "safe": '''@app.route("/download")
def download_file():
    filename = request.args.get("file")
    safe_path = os.path.realpath(os.path.join("/uploads", filename))
    if not safe_path.startswith(os.path.realpath("/uploads")):
        abort(403)
    return send_file(safe_path)''',
                "vuln_description": "No validation of file path allows directory traversal",
                "safe_description": "realpath validation ensures file is within allowed directory",
            },
            {
                "language": "javascript",
                "vulnerable": '''app.get("/files/:name", (req, res) => {
    const filePath = path.join(__dirname, "uploads", req.params.name);
    res.sendFile(filePath);
});''',
                "safe": '''app.get("/files/:name", (req, res) => {
    const filePath = path.resolve(path.join(__dirname, "uploads", req.params.name));
    const uploadsDir = path.resolve(path.join(__dirname, "uploads"));
    if (!filePath.startsWith(uploadsDir)) {
        return res.status(403).send("Forbidden");
    }
    res.sendFile(filePath);
});''',
                "vuln_description": "No path validation allows traversal via ../",
                "safe_description": "Path resolution and prefix check prevents traversal",
            },
            {
                "language": "java",
                "vulnerable": '''@GetMapping("/read")
public String readFile(@RequestParam String filename) throws IOException {
    Path path = Paths.get("/data/" + filename);
    return Files.readString(path);
}''',
                "safe": '''@GetMapping("/read")
public String readFile(@RequestParam String filename) throws IOException {
    Path basePath = Paths.get("/data").toRealPath();
    Path filePath = basePath.resolve(filename).normalize().toRealPath();
    if (!filePath.startsWith(basePath)) {
        throw new SecurityException("Path traversal detected");
    }
    return Files.readString(filePath);
}''',
                "vuln_description": "Direct path construction from user input",
                "safe_description": "Path normalization and prefix validation",
            },
        ]

        # ── 4: Hardcoded Credentials ───────────────────────────────
        templates[4] = [
            {
                "language": "python",
                "vulnerable": '''DB_HOST = "production-db.example.com"
DB_USER = "admin"
DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk-a1b2c3d4e5f6g7h8i9j0"

def connect_db():
    return mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD
    )''',
                "safe": '''import os

DB_HOST = os.environ.get("DB_HOST")
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
API_KEY = os.environ.get("API_KEY")

def connect_db():
    return mysql.connector.connect(
        host=DB_HOST, user=DB_USER, password=DB_PASSWORD
    )''',
                "vuln_description": "Credentials hardcoded in source code",
                "safe_description": "Credentials loaded from environment variables",
            },
            {
                "language": "javascript",
                "vulnerable": '''const config = {
    database: {
        host: "db.production.internal",
        user: "root",
        password: "p@ssw0rd!2024",
    },
    jwt: {
        secret: "my-super-secret-jwt-key-never-share",
    },
    stripe: {
        apiKey: "sk_live_abcdef123456789",
    },
};''',
                "safe": '''require("dotenv").config();

const config = {
    database: {
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
    },
    jwt: {
        secret: process.env.JWT_SECRET,
    },
    stripe: {
        apiKey: process.env.STRIPE_API_KEY,
    },
};''',
                "vuln_description": "API keys and passwords hardcoded in config object",
                "safe_description": "Environment variables used for all secrets",
            },
            {
                "language": "java",
                "vulnerable": '''public class DatabaseConfig {
    private static final String DB_URL = "jdbc:mysql://prod:3306/app";
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "Admin@2024!Secure";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
    }
}''',
                "safe": '''public class DatabaseConfig {
    private static final String DB_URL = System.getenv("DB_URL");
    private static final String DB_USER = System.getenv("DB_USER");
    private static final String DB_PASS = System.getenv("DB_PASS");

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
    }
}''',
                "vuln_description": "Database credentials hardcoded as class constants",
                "safe_description": "Credentials loaded from system environment",
            },
        ]

        # ── 5: Insecure Deserialization ────────────────────────────
        templates[5] = [
            {
                "language": "python",
                "vulnerable": '''import pickle
def load_user_session(session_data):
    return pickle.loads(session_data)''',
                "safe": '''import json
def load_user_session(session_data):
    return json.loads(session_data)''',
                "vuln_description": "pickle.loads on untrusted data enables arbitrary code execution",
                "safe_description": "JSON parsing is safe for deserialization",
            },
            {
                "language": "python",
                "vulnerable": '''import yaml
def load_config(config_str):
    return yaml.load(config_str)''',
                "safe": '''import yaml
def load_config(config_str):
    return yaml.safe_load(config_str)''',
                "vuln_description": "yaml.load without Loader allows arbitrary Python execution",
                "safe_description": "yaml.safe_load only allows basic YAML types",
            },
            {
                "language": "java",
                "vulnerable": '''public Object deserializeObject(byte[] data) throws Exception {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    return ois.readObject();
}''',
                "safe": '''public Object deserializeObject(byte[] data) throws Exception {
    ObjectInputStream ois = new ValidatingObjectInputStream(new ByteArrayInputStream(data));
    ((ValidatingObjectInputStream) ois).accept(SafeClass.class);
    return ois.readObject();
}''',
                "vuln_description": "ObjectInputStream deserializes arbitrary classes",
                "safe_description": "ValidatingObjectInputStream restricts allowed classes",
            },
            {
                "language": "php",
                "vulnerable": '''function loadSession($data) {
    return unserialize($data);
}''',
                "safe": '''function loadSession($data) {
    return json_decode($data, true);
}''',
                "vuln_description": "unserialize on untrusted data can execute arbitrary code",
                "safe_description": "json_decode is safe for deserialization",
            },
        ]

        # ── 6: Weak Cryptography ───────────────────────────────────
        templates[6] = [
            {
                "language": "python",
                "vulnerable": '''import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()''',
                "safe": '''import bcrypt
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())''',
                "vuln_description": "MD5 is cryptographically broken for password hashing",
                "safe_description": "bcrypt with salt is a proper password hashing algorithm",
            },
            {
                "language": "python",
                "vulnerable": '''from Crypto.Cipher import DES
def encrypt_data(key, data):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(data)''',
                "safe": '''from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
def encrypt_data(key, data):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return iv + tag + ciphertext''',
                "vuln_description": "DES with ECB mode is insecure (weak cipher + no IV)",
                "safe_description": "AES-256-GCM with random nonce provides authenticated encryption",
            },
            {
                "language": "javascript",
                "vulnerable": '''const crypto = require("crypto");
function hashPassword(password) {
    return crypto.createHash("sha1").update(password).digest("hex");
}''',
                "safe": '''const bcrypt = require("bcrypt");
async function hashPassword(password) {
    const saltRounds = 12;
    return await bcrypt.hash(password, saltRounds);
}''',
                "vuln_description": "SHA-1 without salt is unsuitable for password hashing",
                "safe_description": "bcrypt with 12 rounds is a secure password hash",
            },
        ]

        # ── 7: Buffer Overflow ─────────────────────────────────────
        templates[7] = [
            {
                "language": "c",
                "vulnerable": '''void process_input(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Received: %s\\n", buffer);
}''',
                "safe": '''void process_input(const char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printf("Received: %s\\n", buffer);
}''',
                "vuln_description": "strcpy with no bounds checking causes buffer overflow",
                "safe_description": "strncpy with explicit size limit prevents overflow",
            },
            {
                "language": "c",
                "vulnerable": '''void get_username() {
    char username[32];
    printf("Enter username: ");
    gets(username);
    printf("Hello, %s\\n", username);
}''',
                "safe": '''void get_username() {
    char username[32];
    printf("Enter username: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\\n")] = '\\0';
    printf("Hello, %s\\n", username);
}''',
                "vuln_description": "gets() has no length limit, always overflows",
                "safe_description": "fgets() with sizeof limit prevents overflow",
            },
            {
                "language": "c",
                "vulnerable": '''void format_message(char *user_msg) {
    char buffer[256];
    sprintf(buffer, "User said: %s at %s", user_msg, get_timestamp());
    log_message(buffer);
}''',
                "safe": '''void format_message(const char *user_msg) {
    char buffer[256];
    snprintf(buffer, sizeof(buffer), "User said: %s at %s", user_msg, get_timestamp());
    log_message(buffer);
}''',
                "vuln_description": "sprintf with no size limit can overflow buffer",
                "safe_description": "snprintf with sizeof limit prevents overflow",
            },
        ]

        # ── 8: Server-Side Request Forgery (SSRF) ─────────────────
        templates[8] = [
            {
                "language": "python",
                "vulnerable": '''import requests

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text''',
                "safe": '''import requests
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        abort(403, "Host not allowed")
    if parsed.scheme not in ("http", "https"):
        abort(403, "Invalid scheme")
    response = requests.get(url, timeout=5)
    return response.text''',
                "vuln_description": "Server fetches arbitrary URLs from user input",
                "safe_description": "URL validation with host allowlist prevents SSRF",
            },
            {
                "language": "javascript",
                "vulnerable": '''app.post("/webhook", async (req, res) => {
    const { callbackUrl } = req.body;
    const response = await fetch(callbackUrl);
    const data = await response.json();
    res.json(data);
});''',
                "safe": '''const { URL } = require("url");

const ALLOWED_HOSTS = new Set(["api.example.com", "hooks.example.com"]);

app.post("/webhook", async (req, res) => {
    const { callbackUrl } = req.body;
    const parsed = new URL(callbackUrl);
    if (!ALLOWED_HOSTS.has(parsed.hostname)) {
        return res.status(403).json({ error: "Host not allowed" });
    }
    const response = await fetch(callbackUrl);
    const data = await response.json();
    res.json(data);
});''',
                "vuln_description": "Callback URL fetched without validation",
                "safe_description": "URL hostname validated against allowlist",
            },
        ]

        # ── 9: Sensitive Data Exposure ─────────────────────────────
        templates[9] = [
            {
                "language": "python",
                "vulnerable": '''@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "ssn": user.ssn,
        "credit_card": user.credit_card,
        "password_hash": user.password_hash,
    })''',
                "safe": '''@app.route("/api/user/<int:user_id>")
def get_user(user_id):
    user = User.query.get(user_id)
    return jsonify({
        "id": user.id,
        "name": user.name,
        "email": user.email,
    })''',
                "vuln_description": "API exposes SSN, credit card, and password hash",
                "safe_description": "API returns only necessary non-sensitive fields",
            },
            {
                "language": "python",
                "vulnerable": '''@app.errorhandler(500)
def internal_error(error):
    return jsonify({
        "error": str(error),
        "traceback": traceback.format_exc(),
        "database": app.config["SQLALCHEMY_DATABASE_URI"],
        "debug_info": {
            "env": dict(os.environ),
        }
    }), 500''',
                "safe": '''@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal error: {error}", exc_info=True)
    return jsonify({
        "error": "An internal error occurred",
        "reference": generate_error_id(),
    }), 500''',
                "vuln_description": "Error handler leaks stack trace, DB URI, and env vars",
                "safe_description": "Generic error message with reference ID for log correlation",
            },
            {
                "language": "javascript",
                "vulnerable": '''app.use((err, req, res, next) => {
    res.status(500).json({
        message: err.message,
        stack: err.stack,
        config: process.env,
    });
});''',
                "safe": '''app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);
    res.status(500).json({
        message: "Internal server error",
        errorId: generateErrorId(),
    });
});''',
                "vuln_description": "Error middleware exposes stack trace and environment",
                "safe_description": "Generic error response with server-side logging",
            },
        ]

        # ── 10: Insecure Randomness ────────────────────────────────
        templates[10] = [
            {
                "language": "python",
                "vulnerable": '''import random
def generate_token():
    return "".join(random.choice("abcdef0123456789") for _ in range(32))

def generate_reset_code():
    return str(random.randint(100000, 999999))''',
                "safe": '''import secrets
def generate_token():
    return secrets.token_hex(16)

def generate_reset_code():
    return f"{secrets.randbelow(900000) + 100000}"''',
                "vuln_description": "random module uses predictable PRNG, not suitable for security",
                "safe_description": "secrets module uses cryptographically secure RNG",
            },
            {
                "language": "javascript",
                "vulnerable": '''function generateSessionId() {
    let id = "";
    for (let i = 0; i < 32; i++) {
        id += Math.floor(Math.random() * 16).toString(16);
    }
    return id;
}''',
                "safe": '''const crypto = require("crypto");
function generateSessionId() {
    return crypto.randomBytes(16).toString("hex");
}''',
                "vuln_description": "Math.random() is not cryptographically secure",
                "safe_description": "crypto.randomBytes uses CSPRNG",
            },
            {
                "language": "java",
                "vulnerable": '''public String generateToken() {
    Random random = new Random();
    StringBuilder token = new StringBuilder();
    for (int i = 0; i < 32; i++) {
        token.append(Integer.toHexString(random.nextInt(16)));
    }
    return token.toString();
}''',
                "safe": '''public String generateToken() {
    SecureRandom secureRandom = new SecureRandom();
    byte[] bytes = new byte[16];
    secureRandom.nextBytes(bytes);
    return DatatypeConverter.printHexBinary(bytes).toLowerCase();
}''',
                "vuln_description": "java.util.Random is predictable for security tokens",
                "safe_description": "SecureRandom uses cryptographically strong RNG",
            },
        ]

        return templates

    def get_class_distribution(self, samples: list[dict]) -> dict[str, int]:
        """
        Get the distribution of vulnerability classes in generated samples.
        
        Args:
            samples: List of generated sample dicts.
            
        Returns:
            Dictionary mapping class names to counts.
        """
        dist = {"Safe": 0}
        for name in self.VULN_CLASSES.values():
            dist[name] = 0

        for sample in samples:
            if sample["is_vulnerable"]:
                dist[sample["vulnerability_name"]] += 1
            else:
                dist["Safe"] += 1

        return dist
