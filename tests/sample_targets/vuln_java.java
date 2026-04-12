// Broken Wings — Test Sample Target (Java)
// This file contains intentionally vulnerable Java code.

import java.sql.*;
import java.io.*;
import java.util.Random;
import java.security.MessageDigest;

public class VulnJava {

    // ── VULN: Hardcoded Credentials (CWE-798) ──────────
    private static final String DB_URL = "jdbc:mysql://prod:3306/app";
    private static final String DB_USER = "admin";
    private static final String DB_PASS = "Admin@2024!Prod";

    // ── VULN: SQL Injection (CWE-89) ────────────────────
    public ResultSet findUser(String username) throws SQLException {
        Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE name = '" + username + "'";
        return stmt.executeQuery(query);
    }

    // ── VULN: Command Injection (CWE-78) ────────────────
    public String checkHost(String hostname) throws Exception {
        Process p = Runtime.getRuntime().exec("ping -c 4 " + hostname);
        BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        return output.toString();
    }

    // ── VULN: Path Traversal (CWE-22) ──────────────────
    public String readFile(String filename) throws IOException {
        Path path = Paths.get("/data/" + filename);
        return Files.readString(path);
    }

    // ── VULN: Weak Cryptography (CWE-327) ──────────────
    public String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] hash = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // ── VULN: Insecure Randomness (CWE-330) ────────────
    public String generateToken() {
        Random random = new Random();
        StringBuilder token = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            token.append(Integer.toHexString(random.nextInt(16)));
        }
        return token.toString();
    }

    // ── VULN: Insecure Deserialization (CWE-502) ───────
    public Object loadObject(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(
            new ByteArrayInputStream(data)
        );
        return ois.readObject();
    }

    // ── VULN: Buffer Overflow style (String concat) ────
    public String processInput(String userInput) {
        // While Java has bounds checking, this pattern shows
        // unsafe string handling similar to buffer overflow in C
        char[] buffer = new char[64];
        // Simulated unsafe copy
        userInput.getChars(0, userInput.length(), buffer, 0);
        return new String(buffer);
    }

    // ── VULN: Sensitive Data Exposure (CWE-200) ────────
    public String handleError(Exception e) {
        StringWriter sw = new StringWriter();
        e.printStackTrace(new PrintWriter(sw));
        return "{\"error\": \"" + e.getMessage() + "\", " +
               "\"stackTrace\": \"" + sw.toString() + "\", " +
               "\"dbUrl\": \"" + DB_URL + "\"}";
    }
}
