// Broken Wings — Test Sample Target (JavaScript)
// This file contains intentionally vulnerable JavaScript code.

const { exec } = require("child_process");
const mysql = require("mysql");
const express = require("express");
const app = express();

// ── VULN: Hardcoded Credentials (CWE-798) ──────────────
const config = {
    database: {
        host: "production-db.internal",
        user: "root",
        password: "RootP@ssw0rd!2024",
    },
    jwt: {
        secret: "jwt-signing-key-super-secret-never-reveal",
    },
    stripe: {
        apiKey: "sk_test_placeholder_key_for_testing",
    },
};

const db = mysql.createConnection(config.database);

// ── VULN: SQL Injection (CWE-89) ───────────────────────
app.get("/users", (req, res) => {
    const id = req.query.id;
    const query = "SELECT * FROM users WHERE id = " + id;
    db.query(query, (err, results) => {
        if (err) return res.status(500).send(err.message);
        res.json(results);
    });
});

// ── VULN: XSS (CWE-79) ─────────────────────────────────
app.get("/profile", (req, res) => {
    const name = req.query.name;
    res.send(`<html><body><h1>Hello ${name}!</h1></body></html>`);
});

app.get("/comments", (req, res) => {
    const comment = req.query.text;
    document.getElementById("output").innerHTML = comment;
});

// ── VULN: Command Injection (CWE-78) ───────────────────
app.get("/dns", (req, res) => {
    exec("nslookup " + req.query.domain, (err, stdout) => {
        res.send(`<pre>${stdout}</pre>`);
    });
});

// ── VULN: Insecure Randomness (CWE-330) ────────────────
function generateToken() {
    let token = "";
    for (let i = 0; i < 32; i++) {
        token += Math.floor(Math.random() * 16).toString(16);
    }
    return token;
}

// ── VULN: Sensitive Data Exposure (CWE-200) ─────────────
app.use((err, req, res, next) => {
    console.log("Error with password:", config.database.password);
    res.status(500).json({
        message: err.message,
        stack: err.stack,
        config: process.env,
    });
});

// ── VULN: SSRF (CWE-918) ───────────────────────────────
app.post("/fetch", async (req, res) => {
    const { url } = req.body;
    const response = await fetch(url);
    const data = await response.text();
    res.send(data);
});

app.listen(3000);
