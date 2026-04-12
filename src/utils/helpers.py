"""
BAYREUTHWING — Helper Utilities

File handling, language detection, and code file discovery functions.
"""

import os
from pathlib import Path
from typing import Optional


# Supported code file extensions
CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx",
    ".java", ".c", ".h", ".cpp", ".hpp", ".cc", ".cxx",
    ".php", ".rb", ".go", ".rs",
}

EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".java": "java",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".php": "php",
    ".rb": "ruby",
    ".go": "go",
    ".rs": "rust",
}

# Directories to skip during scanning
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "env", ".env", "dist", "build", ".tox", ".mypy_cache",
    ".pytest_cache", "vendor", "target", "bin", "obj",
    ".idea", ".vscode", ".vs", "coverage", ".next",
}

# Maximum file size to scan (5 MB)
MAX_FILE_SIZE = 5 * 1024 * 1024


def detect_file_language(filepath: str) -> str:
    """
    Detect programming language from file extension.
    
    Args:
        filepath: Path to the file.
        
    Returns:
        Language string (e.g., 'python', 'javascript') or 'unknown'.
    """
    ext = Path(filepath).suffix.lower()
    return EXTENSION_TO_LANGUAGE.get(ext, "unknown")


def read_file_safe(filepath: str, max_size: int = MAX_FILE_SIZE) -> Optional[str]:
    """
    Safely read a file's contents with size limit.
    
    Args:
        filepath: Path to the file.
        max_size: Maximum file size in bytes.
        
    Returns:
        File contents as string, or None if file can't be read.
    """
    try:
        path = Path(filepath)
        if not path.exists() or not path.is_file():
            return None

        if path.stat().st_size > max_size:
            return None

        # Try UTF-8 first, fall back to latin-1
        try:
            return path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            return path.read_text(encoding="latin-1")
    except (OSError, PermissionError):
        return None


def find_code_files(
    path: str,
    recursive: bool = True,
    extensions: Optional[set[str]] = None,
    max_files: int = 10000,
) -> list[str]:
    """
    Find all code files under a given path.
    
    Skips common non-code directories (node_modules, .git, etc.)
    and respects file size limits.
    
    Args:
        path: File or directory path to scan.
        recursive: If True, scan subdirectories.
        extensions: Set of file extensions to include. Defaults to CODE_EXTENSIONS.
        max_files: Maximum number of files to return.
        
    Returns:
        List of file paths.
    """
    target = Path(path)
    valid_extensions = extensions or CODE_EXTENSIONS
    files = []

    if target.is_file():
        if target.suffix.lower() in valid_extensions:
            return [str(target)]
        return []

    if not target.is_dir():
        return []

    def _scan_dir(directory: Path):
        if len(files) >= max_files:
            return

        try:
            entries = sorted(directory.iterdir())
        except PermissionError:
            return

        for entry in entries:
            if len(files) >= max_files:
                return

            if entry.is_dir():
                if entry.name in SKIP_DIRS:
                    continue
                if recursive:
                    _scan_dir(entry)
            elif entry.is_file():
                if entry.suffix.lower() in valid_extensions:
                    try:
                        if entry.stat().st_size <= MAX_FILE_SIZE:
                            files.append(str(entry))
                    except OSError:
                        pass

    _scan_dir(target)
    return files


def format_file_size(size_bytes: int) -> str:
    """Format byte count as human-readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def get_line_context(
    code: str,
    line_number: int,
    context_lines: int = 3,
) -> dict:
    """
    Get a code snippet centered on a specific line number.
    
    Args:
        code: Full source code.
        line_number: Target line (1-indexed).
        context_lines: Number of lines above/below to include.
        
    Returns:
        Dict with 'snippet', 'start_line', 'end_line', 'target_line'.
    """
    lines = code.split("\n")
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)

    snippet_lines = []
    for i in range(start, end):
        prefix = ">>> " if (i + 1) == line_number else "    "
        snippet_lines.append(f"{prefix}{i + 1:4d} | {lines[i]}")

    return {
        "snippet": "\n".join(snippet_lines),
        "start_line": start + 1,
        "end_line": end,
        "target_line": line_number,
    }
