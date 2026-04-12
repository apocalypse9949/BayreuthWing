"""
BAYREUTHWING — CLI Interface

Rich command-line interface with admin control capabilities.
Supports scanning, training, and demo modes.

Usage:
    python cli.py scan <path> [--recursive] [--format console|json|html] [--output report.html]
    python cli.py train [--epochs 50] [--batch-size 32] [--samples 5000]
    python cli.py demo
    python cli.py info
"""

import os
import sys
import time
import click
import yaml

# Add parent to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def load_config():
    """Load configuration from model_config.yaml."""
    config_path = os.path.join(os.path.dirname(__file__), "config", "model_config.yaml")
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            return yaml.safe_load(f)
    return {}


def print_banner():
    """Print the BayreuthWing banner."""
    banner = """
\033[38;5;99m╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗  █████╗ ██╗   ██╗██████╗ ███████╗██╗   ██╗████████╗║
║   ██╔══██╗██╔══██╗╚██╗ ██╔╝██╔══██╗██╔════╝██║   ██║╚══██╔══╝║
║   ██████╔╝███████║ ╚████╔╝ ██████╔╝█████╗  ██║   ██║   ██║   ║
║   ██╔══██╗██╔══██║  ╚██╔╝  ██╔══██╗██╔══╝  ██║   ██║   ██║   ║
║   ██████╔╝██║  ██║   ██║   ██║  ██║███████╗╚██████╔╝   ██║   ║
║   ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝    ╚═╝   ║
║                                                              ║
║            ██╗    ██╗██║███╗   ██╗ ██████╗                   ║
║            ██║    ██║██║████╗  ██║██╔════╝                   ║
║            ██║ █╗ ██║██║██╔██╗ ██║██║  ███╗                  ║
║            ██║███╗██║██║██║╚██╗██║██║   ██║                  ║
║            ╚███╔███╔╝██║██║ ╚████║╚██████╔╝                  ║
║             ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝ ╚═════╝                  ║
║                                                              ║
║        AI-Powered Code Vulnerability Scanner v1.0.0          ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝\033[0m
"""
    print(banner)


@click.group()
@click.version_option(version="1.0.0", prog_name="BAYREUTHWING")
def main():
    """BAYREUTHWING -- AI-Powered Code Vulnerability Scanner"""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option("--recursive", "-r", is_flag=True, default=True, help="Scan directories recursively")
@click.option("--format", "-f", "output_format", type=click.Choice(["console", "json", "html"]), default="console", help="Report format")
@click.option("--output", "-o", "output_path", type=click.Path(), default=None, help="Output file path for report")
@click.option("--model", "-m", "model_path", type=click.Path(), default=None, help="Path to trained model checkpoint")
@click.option("--threshold", "-t", type=float, default=0.5, help="Confidence threshold (0.0-1.0)")
@click.option("--no-ml", is_flag=True, default=False, help="Disable ML inference (rules-only mode)")
@click.option("--no-rules", is_flag=True, default=False, help="Disable static rules")
@click.option("--no-flow", is_flag=True, default=False, help="Disable code flow analysis")
def scan(path, recursive, output_format, output_path, model_path, threshold, no_ml, no_rules, no_flow):
    """Scan code for security vulnerabilities."""
    print_banner()
    config = load_config()

    # Override config with CLI flags
    if "scanner" not in config:
        config["scanner"] = {}
    config["scanner"]["confidence_threshold"] = threshold

    if "modules" not in config["scanner"]:
        config["scanner"]["modules"] = {}
    config["scanner"]["modules"]["code_analysis"] = {"enabled": not no_rules}
    config["scanner"]["modules"]["architecture_analysis"] = {"enabled": not no_flow}

    from src.scanner.engine import ScanEngine
    from src.scanner.reporter import ReportGenerator

    # Load model if available
    model = None
    tokenizer = None
    if not no_ml:
        default_model = os.path.join("checkpoints", "model_best.pt")
        mp = model_path or (default_model if os.path.exists(default_model) else None)
        if mp:
            print(f"  Loading model from: {mp}")

    print(f"\n  🔍 Scanning: {os.path.abspath(path)}")
    print(f"  {'─' * 50}")

    # Create scanner
    engine = ScanEngine(model=model, tokenizer=tokenizer, config=config, model_path=model_path)

    # Progress callback
    def progress(current, total, filepath):
        rel_path = os.path.relpath(filepath, path) if os.path.isdir(path) else filepath
        bar_len = 30
        filled = int(bar_len * current / total)
        bar = "█" * filled + "░" * (bar_len - filled)
        print(f"\r  [{bar}] {current}/{total} {rel_path[:40]:<40}", end="", flush=True)

    # Run scan
    results = engine.scan_directory(path, recursive=recursive, progress_callback=progress)
    print("\n")

    # Generate report
    reporter = ReportGenerator()
    report = reporter.generate(results, output_path=output_path, format=output_format)

    if output_format == "console":
        print(report)
    elif output_path:
        print(f"  📋 Report saved to: {os.path.abspath(output_path)}")
    else:
        print(report)

    # Exit code based on findings
    if results.get("severity_counts", {}).get("critical", 0) > 0:
        sys.exit(2)
    elif results.get("total_findings", 0) > 0:
        sys.exit(1)
    sys.exit(0)


@main.command()
@click.option("--epochs", "-e", type=int, default=50, help="Number of training epochs")
@click.option("--batch-size", "-b", type=int, default=32, help="Training batch size")
@click.option("--samples", "-s", type=int, default=5000, help="Number of synthetic training samples")
@click.option("--lr", type=float, default=3e-4, help="Learning rate")
@click.option("--checkpoint-dir", type=click.Path(), default="checkpoints", help="Checkpoint directory")
def train(epochs, batch_size, samples, lr, checkpoint_dir):
    """Train the CodeTransformer model."""
    print_banner()
    print("  🧠 Training Mode")
    print(f"  {'─' * 50}")

    config = load_config()

    # Override config with CLI args
    if "training" not in config:
        config["training"] = {}
    config["training"]["epochs"] = epochs
    config["training"]["batch_size"] = batch_size
    config["training"]["learning_rate"] = lr
    config["training"]["synthetic_samples"] = samples
    config["training"]["checkpoint_dir"] = checkpoint_dir

    import torch
    from src.model.transformer import CodeTransformer
    from src.model.tokenizer import CodeTokenizer
    from src.data.generator import SyntheticDataGenerator
    from src.data.dataset import VulnCodeDataset
    from src.training.trainer import Trainer

    # Generate synthetic data
    print(f"\n  📊 Generating {samples} synthetic training samples...")
    generator = SyntheticDataGenerator(seed=42)
    data = generator.generate(num_samples=samples)

    dist = generator.get_class_distribution(data)
    print("  Class distribution:")
    for name, count in sorted(dist.items(), key=lambda x: -x[1]):
        print(f"    {name:<35}: {count}")

    # Create dataset and split
    print("\n  📦 Creating datasets...")
    tokenizer = CodeTokenizer(max_length=512)
    dataset = VulnCodeDataset(data, tokenizer=tokenizer, max_length=512)
    train_ds, val_ds, test_ds = dataset.split()
    print(f"    Train: {len(train_ds)} | Val: {len(val_ds)} | Test: {len(test_ds)}")

    # Create model
    print("\n  🏗️  Building CodeTransformer model...")
    model = CodeTransformer.from_config(config)
    params = model.count_parameters()
    for component, count in params.items():
        print(f"    {component:<20}: {count:>12,}")

    # Train
    trainer = Trainer(model, train_ds, val_ds, config=config)
    print(f"\n  Device: {trainer.device}")
    print(f"  Mixed Precision: {trainer.mixed_precision}")
    print()

    history = trainer.train(verbose=True)

    # Evaluate on test set
    print("\n  📊 Evaluating on test set...")
    from src.training.evaluator import Evaluator
    evaluator = Evaluator(num_classes=model.num_vuln_classes, class_names=[
        "SQL Injection", "XSS", "Command Injection", "Path Traversal",
        "Hardcoded Credentials", "Insecure Deserialization",
        "Weak Cryptography", "Buffer Overflow", "SSRF",
        "Data Exposure", "Insecure Random",
    ])

    model.eval()
    from torch.utils.data import DataLoader
    test_loader = DataLoader(test_ds, batch_size=batch_size, collate_fn=VulnCodeDataset.collate_fn)

    with torch.no_grad():
        for batch in test_loader:
            input_ids = batch["input_ids"].to(trainer.device)
            token_type_ids = batch["token_type_ids"].to(trainer.device)
            outputs = model(input_ids, token_type_ids=token_type_ids)
            evaluator.update(outputs["probabilities"], batch["labels"])

    metrics = evaluator.compute_metrics()
    print(evaluator.format_report(metrics))

    print(f"\n  ✅ Training complete. Model saved to: {checkpoint_dir}/")


@main.command()
def demo():
    """Run interactive demo with sample vulnerable code."""
    print_banner()
    print("  🎯 Demo Mode — Scanning sample vulnerable code")
    print(f"  {'─' * 50}\n")

    from src.scanner.engine import ScanEngine
    from src.scanner.reporter import ReportGenerator

    # Create sample vulnerable files in memory
    samples = {
        "demo_python.py": '''import os
import pickle
import hashlib
import random

DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk-a1b2c3d4e5f6g7h8i9j0klmnop"

def get_user(username):
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchone()

def run_command(user_input):
    os.system("ping -c 4 " + user_input)

def load_session(data):
    return pickle.loads(data)

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    return str(random.randint(100000, 999999))

@app.route("/download")
def download():
    filename = request.args.get("file")
    return send_file(os.path.join("/uploads", filename))

@app.route("/search")
def search():
    q = request.args.get("q", "")
    return f"<h2>Results for: {q}</h2>"

@app.route("/fetch")
def fetch_url():
    url = request.args.get("url")
    response = requests.get(url)
    return response.text

@app.errorhandler(500)
def error(e):
    return jsonify({
        "error": str(e),
        "traceback": traceback.format_exc(),
    }), 500
''',
        "demo_javascript.js": '''const { exec } = require("child_process");

const config = {
    db: {
        host: "prod-db.internal",
        user: "admin",
        password: "Admin@2024!Pass",
    },
    jwt: {
        secret: "my-jwt-secret-never-share-this",
    },
};

app.get("/users", (req, res) => {
    const name = req.query.name;
    const query = "SELECT * FROM users WHERE name = '" + name + "'";
    db.query(query, (err, results) => {
        res.json(results);
    });
});

app.get("/run", (req, res) => {
    exec("nslookup " + req.query.host, (err, stdout) => {
        res.send(stdout);
    });
});

app.get("/profile", (req, res) => {
    const name = req.query.name;
    res.send("<h1>Welcome " + name + "</h1>");
});

function generateSessionId() {
    let id = "";
    for (let i = 0; i < 32; i++) {
        id += Math.floor(Math.random() * 16).toString(16);
    }
    return id;
}

app.use((err, req, res, next) => {
    res.status(500).json({
        message: err.message,
        stack: err.stack,
    });
});
''',
    }

    # Write demo files temporarily
    demo_dir = os.path.join(os.path.dirname(__file__), "_demo_scan_target")
    os.makedirs(demo_dir, exist_ok=True)

    for filename, code in samples.items():
        filepath = os.path.join(demo_dir, filename)
        with open(filepath, "w") as f:
            f.write(code)

    # Scan
    config = load_config()
    engine = ScanEngine(config=config)

    print("  Scanning demo files...\n")
    results = engine.scan_directory(demo_dir)

    reporter = ReportGenerator()
    report = reporter.generate(results, format="console")
    print(report)

    # Also generate HTML report
    html_path = os.path.join(demo_dir, "demo_report.html")
    reporter.generate(results, output_path=html_path, format="html")
    print(f"  📄 HTML report saved: {html_path}")

    # Cleanup option
    print(f"\n  Demo files are in: {demo_dir}")
    print("  You can delete them when done.")


# ═══════════════════════════════════════════════════════════════
# INTERNET-CONNECTED INTELLIGENCE COMMANDS
# ═══════════════════════════════════════════════════════════════


@main.command("github-scan")
@click.argument("repo_url")
@click.option("--branch", "-b", default=None, help="Branch to scan (default: main)")
@click.option("--format", "-f", "output_format", type=click.Choice(["console", "json", "html"]), default="console")
@click.option("--output", "-o", "output_path", type=click.Path(), default=None)
@click.option("--keep", is_flag=True, default=False, help="Keep cloned repo after scan")
def github_scan(repo_url, branch, output_format, output_path, keep):
    """Scan a GitHub repository by URL (requires internet)."""
    print_banner()
    print("  REMOTE REPOSITORY SCAN")
    print(f"  {'─' * 50}")
    print(f"  Target: {repo_url}")
    if branch:
        print(f"  Branch: {branch}")
    print()

    from src.intel.github_scanner import GitHubScanner
    from src.scanner.engine import ScanEngine
    from src.scanner.reporter import ReportGenerator

    scanner = GitHubScanner()
    engine = ScanEngine(config=load_config())

    results = scanner.clone_and_scan(
        repo_url,
        branch=branch,
        scan_engine=engine,
        cleanup=not keep,
    )

    if "error" in results:
        print(f"  ERROR: {results['error']}")
        sys.exit(1)

    # Print repo info
    repo_info = results.get("repo_info")
    if repo_info:
        print(f"\n  REPOSITORY INFO:")
        print(f"    Name:     {repo_info.get('full_name', 'N/A')}")
        print(f"    Language: {repo_info.get('language', 'N/A')}")
        print(f"    Stars:    {repo_info.get('stars', 0):,}")
        print(f"    License:  {repo_info.get('license', 'N/A')}")
        print()

    # Print code scan summary
    code_scan = results.get("code_scan", {})
    summary = results.get("scan_summary", {})
    print(f"  SCAN SUMMARY:")
    print(f"    Files Scanned:       {summary.get('files_scanned', 0)}")
    print(f"    Code Findings:       {summary.get('code_findings', 0)}")
    print(f"    Vulnerable Deps:     {summary.get('dep_vulnerabilities', 0)}")
    print(f"    GitHub Advisories:   {summary.get('advisories', 0)}")
    print()

    # Generate code scan report
    reporter = ReportGenerator()
    report = reporter.generate(code_scan, output_path=output_path, format=output_format)

    if output_format == "console":
        print(report)
    elif output_path:
        print(f"  Report saved to: {os.path.abspath(output_path)}")

    # Print dependency vulnerabilities
    dep_vulns = results.get("dependency_scan", {}).get("vulnerabilities", [])
    if dep_vulns:
        print("\n  VULNERABLE DEPENDENCIES:")
        print("  " + "-" * 55)
        for v in dep_vulns[:10]:
            print(f"    [{v.get('severity', 'N/A'):>8}] {v['package']}@{v.get('package_version', '?')}")
            print(f"             {v.get('summary', '')[:80]}")
            print()


@main.command("deps")
@click.argument("path", type=click.Path(exists=True))
@click.option("--format", "-f", "output_format", type=click.Choice(["console", "json"]), default="console")
@click.option("--output", "-o", "output_path", type=click.Path(), default=None)
def check_deps(path, output_format, output_path):
    """Scan project dependencies for known vulnerabilities (requires internet)."""
    print_banner()
    print("  DEPENDENCY VULNERABILITY SCAN")
    print(f"  {'─' * 50}")
    print(f"  Target: {os.path.abspath(path)}")
    print()
    print("  Checking packages against OSV.dev database...")
    print()

    from src.intel.dependency_checker import DependencyChecker
    import json as json_mod

    checker = DependencyChecker()
    results = checker.scan_project(path)

    if output_format == "json":
        json_str = json_mod.dumps(results, indent=2, default=str)
        if output_path:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            with open(output_path, "w") as f:
                f.write(json_str)
            print(f"  Report saved to: {output_path}")
        else:
            print(json_str)
    else:
        report = checker.format_report(results)
        print(report)

    if results["vulnerable_dependencies"] > 0:
        sys.exit(1)
    sys.exit(0)


@main.command("cve-search")
@click.argument("query")
@click.option("--cwe", "by_cwe", is_flag=True, default=False, help="Search by CWE ID instead of keyword")
@click.option("--severity", "-s", type=click.Choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"]), default=None)
@click.option("--max-results", "-n", type=int, default=10, help="Max results to return")
@click.option("--api-key", envvar="NVD_API_KEY", default=None, help="NVD API key (or set NVD_API_KEY env var)")
def cve_search(query, by_cwe, severity, max_results, api_key):
    """Search the NVD database for CVEs (requires internet)."""
    print_banner()
    print("  CVE / NVD SEARCH")
    print(f"  {'─' * 50}")

    from src.intel.cve_client import CVEClient

    client = CVEClient(api_key=api_key)

    if by_cwe:
        print(f"  Searching NVD for CWE: {query}")
        cwe_id = query if query.startswith("CWE-") else f"CWE-{query}"
        results = client.search_by_cwe(cwe_id, max_results=max_results)
    elif query.upper().startswith("CVE-"):
        print(f"  Fetching CVE: {query}")
        result = client.get_cve(query)
        results = [result] if result else []
    else:
        print(f"  Searching NVD for: {query}")
        results = client.search_by_keyword(query, max_results=max_results, severity=severity)

    print(f"  Found: {len(results)} results")
    print()

    if not results:
        print("  No CVEs found matching your query.")
        return

    for cve in results:
        score = cve.get("cvss_score")
        sev = cve.get("cvss_severity", "N/A")
        score_str = f"{score:.1f}" if score else "N/A"

        print(f"  {cve['cve_id']}")
        print(f"    CVSS: {score_str} ({sev})")
        print(f"    Published: {cve.get('published', 'N/A')}")
        if cve.get("cwe_ids"):
            print(f"    CWEs: {', '.join(cve['cwe_ids'])}")
        print(f"    {cve.get('description', 'No description')[:120]}")
        if cve.get("references"):
            print(f"    Ref: {cve['references'][0].get('url', '')}")
        print()


@main.command("threats")
@click.option("--days", "-d", type=int, default=30, help="Days back for recent threats")
@click.option("--search", "-s", "search_term", default=None, help="Search KEV catalog")
@click.option("--check-cve", default=None, help="Check if a specific CVE is actively exploited")
def threat_intel(days, search_term, check_cve):
    """View real-time threat intelligence from CISA KEV (requires internet)."""
    print_banner()
    print("  THREAT INTELLIGENCE")
    print(f"  {'─' * 50}")
    print()

    from src.intel.threat_feed import ThreatIntelFeed

    feed = ThreatIntelFeed()

    if check_cve:
        print(f"  Checking if {check_cve} is actively exploited...")
        kev = feed.check_cve_in_kev(check_cve)
        if kev:
            print(f"\n  *** ACTIVELY EXPLOITED ***")
            print(f"  CVE:         {kev['cve_id']}")
            print(f"  Vendor:      {kev['vendor']}")
            print(f"  Product:     {kev['product']}")
            print(f"  Name:        {kev['name']}")
            print(f"  Date Added:  {kev['date_added']}")
            print(f"  Due Date:    {kev['due_date']}")
            print(f"  Ransomware:  {kev['known_ransomware']}")
            print(f"  Action:      {kev['required_action'][:100]}")
        else:
            print(f"\n  {check_cve} is NOT in the CISA KEV catalog.")
        print()
        return

    if search_term:
        print(f"  Searching KEV catalog for: {search_term}")
        results = feed.search_kev(search_term)
        print(f"  Found: {len(results)} matches\n")
        for v in results[:15]:
            print(f"    {v['cve_id']:<18} {v['vendor']}/{v['product']}")
            print(f"      {v['description'][:80]}")
            rw = v.get('known_ransomware', 'Unknown')
            if rw.lower() == 'known':
                print(f"      *** Ransomware Associated ***")
            print()
        return

    # Default: show threat summary
    print("  Fetching threat landscape from CISA KEV...")
    summary = feed.get_threat_summary()
    report = feed.format_threat_report(summary)
    print(report)


@main.command()
def info():
    """Display system information and capabilities."""
    print_banner()

    import torch
    from src.scanner.rules import RuleEngine
    from src.utils.cwe_mapping import CWEMapper

    print("  SYSTEM INFORMATION")
    print(f"  {'─' * 50}")
    print(f"  Python:         {sys.version.split()[0]}")
    print(f"  PyTorch:        {torch.__version__}")
    print(f"  CUDA Available: {torch.cuda.is_available()}")
    if torch.cuda.is_available():
        print(f"  GPU:            {torch.cuda.get_device_name(0)}")
    print()

    print("  VULNERABILITY CLASSES:")
    print(f"  {'─' * 50}")
    classes = CWEMapper.get_all_classes()
    for vuln_id, name in classes.items():
        info = CWEMapper.get_info(vuln_id)
        print(f"    {vuln_id:>2}. {name:<35} {info['cwe_id']:<10} {info['severity']}")
    print()

    rules = RuleEngine()
    print(f"  STATIC RULES: {rules.total_rules} patterns")
    print(f"  {'─' * 50}")
    summary = rules.rules_summary()
    for name, count in sorted(summary.items(), key=lambda x: -x[1]):
        bar = "█" * count
        print(f"    {name:<35} {count:>3} {bar}")
    print()

    # Check for trained model
    model_path = os.path.join("checkpoints", "model_best.pt")
    if os.path.exists(model_path):
        size_mb = os.path.getsize(model_path) / (1024 * 1024)
        print(f"  TRAINED MODEL: Found ({size_mb:.1f} MB)")
    else:
        print("  TRAINED MODEL: Not found (run 'python cli.py train' to create)")
    print()

    # Internet modules
    print("  INTERNET MODULES:")
    print(f"  {'─' * 50}")
    print("    cve-search    Search NVD for CVEs by keyword, CWE, or CVE ID")
    print("    deps          Check project dependencies against OSV.dev")
    print("    github-scan   Clone and scan a GitHub repo by URL")
    print("    threats       View CISA KEV active exploitation data")
    print()


if __name__ == "__main__":
    main()
