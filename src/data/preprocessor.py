"""
BAYREUTHWING — Code Preprocessor

Normalizes and cleans source code before tokenization. Handles:
- Consistent line endings
- Comment normalization
- Whitespace standardization
- Language detection
- Code snippet extraction for large files
"""

import re
from pathlib import Path


# ─── Language detection by file extension ───────────────────────────
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

# ─── Framework detection patterns ───────────────────────────────────
FRAMEWORK_PATTERNS = {
    "django": [
        r"from\s+django",
        r"import\s+django",
        r"DJANGO_SETTINGS_MODULE",
        r"urls\.py",
        r"views\.py",
    ],
    "flask": [
        r"from\s+flask\s+import",
        r"Flask\s*\(",
        r"@app\.route",
    ],
    "fastapi": [
        r"from\s+fastapi\s+import",
        r"FastAPI\s*\(",
        r"@app\.(get|post|put|delete|patch)",
    ],
    "express": [
        r"require\s*\(\s*['\"]express['\"]\s*\)",
        r"express\s*\(\s*\)",
        r"app\.(get|post|put|delete|patch|use)\s*\(",
    ],
    "react": [
        r"import\s+React",
        r"from\s+['\"]react['\"]",
        r"useState|useEffect|useContext",
        r"ReactDOM",
    ],
    "spring": [
        r"@SpringBootApplication",
        r"@RestController",
        r"@RequestMapping",
        r"import\s+org\.springframework",
    ],
    "rails": [
        r"class\s+\w+\s*<\s*ApplicationController",
        r"ActiveRecord::Base",
        r"Rails\.application",
    ],
    "laravel": [
        r"use\s+Illuminate",
        r"class\s+\w+\s+extends\s+Controller",
        r"Route::(get|post|put|delete)",
    ],
    "gin": [
        r"\"github\.com/gin-gonic/gin\"",
        r"gin\.Default\(\)",
        r"gin\.New\(\)",
    ],
    "actix": [
        r"use\s+actix_web",
        r"HttpServer::new",
        r"#\[actix_web::main\]",
    ],
}


class CodePreprocessor:
    """
    Preprocesses source code for the vulnerability scanner.
    
    Handles normalization, language/framework detection, and chunking
    of large files into analyzable segments.
    """

    def __init__(self, max_chunk_size: int = 2000, overlap: int = 200):
        """
        Args:
            max_chunk_size: Maximum characters per code chunk.
            overlap: Character overlap between consecutive chunks.
        """
        self.max_chunk_size = max_chunk_size
        self.overlap = overlap

    def normalize(self, code: str) -> str:
        """
        Normalize source code for consistent processing.
        
        - Standardize line endings to \\n
        - Remove trailing whitespace from lines
        - Limit consecutive blank lines to 2
        - Ensure file ends with newline
        
        Args:
            code: Raw source code string.
            
        Returns:
            Normalized code string.
        """
        # Standardize line endings
        code = code.replace("\r\n", "\n").replace("\r", "\n")

        # Remove trailing whitespace per line
        lines = [line.rstrip() for line in code.split("\n")]

        # Collapse excessive blank lines (max 2 consecutive)
        normalized_lines = []
        blank_count = 0
        for line in lines:
            if line == "":
                blank_count += 1
                if blank_count <= 2:
                    normalized_lines.append(line)
            else:
                blank_count = 0
                normalized_lines.append(line)

        code = "\n".join(normalized_lines)

        # Ensure trailing newline
        if not code.endswith("\n"):
            code += "\n"

        return code

    def detect_language(self, code: str, filepath: str | None = None) -> str:
        """
        Detect the programming language of the code.
        
        Uses file extension first, falls back to content-based heuristics.
        
        Args:
            code: Source code string.
            filepath: Optional file path for extension-based detection.
            
        Returns:
            Detected language string (e.g., 'python', 'javascript').
        """
        # Try extension first
        if filepath:
            ext = Path(filepath).suffix.lower()
            if ext in EXTENSION_TO_LANGUAGE:
                return EXTENSION_TO_LANGUAGE[ext]

        # Content-based heuristics
        heuristics = [
            ("python", [r"def\s+\w+\s*\(", r"import\s+\w+", r"class\s+\w+\s*:", r"print\s*\("]),
            ("javascript", [r"function\s+\w+\s*\(", r"const\s+\w+\s*=", r"let\s+\w+\s*=", r"=>\s*\{"]),
            ("java", [r"public\s+class", r"public\s+static\s+void\s+main", r"System\.out\."]),
            ("c", [r"#include\s*<", r"int\s+main\s*\(", r"printf\s*\(", r"malloc\s*\("]),
            ("cpp", [r"#include\s*<iostream>", r"std::", r"cout\s*<<", r"namespace\s+\w+"]),
            ("go", [r"package\s+\w+", r"func\s+\w+\s*\(", r"fmt\.\w+", r"go\s+func"]),
            ("rust", [r"fn\s+\w+\s*\(", r"let\s+mut\s+", r"impl\s+\w+", r"use\s+std::"]),
            ("php", [r"<\?php", r"\$\w+\s*=", r"function\s+\w+\s*\(.*\)\s*\{"]),
            ("ruby", [r"def\s+\w+", r"class\s+\w+\s*<", r"require\s+['\"]", r"puts\s+"]),
        ]

        scores = {}
        for lang, patterns in heuristics:
            score = sum(1 for p in patterns if re.search(p, code))
            if score > 0:
                scores[lang] = score

        if scores:
            return max(scores, key=scores.get)

        return "unknown"

    def detect_frameworks(self, code: str) -> list[str]:
        """
        Detect web frameworks and libraries used in the code.
        
        This enables adaptive analysis — different frameworks have
        different security patterns and common vulnerabilities.
        
        Args:
            code: Source code string.
            
        Returns:
            List of detected framework names.
        """
        detected = []
        for framework, patterns in FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, code):
                    detected.append(framework)
                    break
        return detected

    def chunk_code(self, code: str) -> list[dict]:
        """
        Split large code files into overlapping chunks for analysis.
        
        Tries to split at function/class boundaries when possible.
        Each chunk includes metadata about its position in the original file.
        
        Args:
            code: Source code string.
            
        Returns:
            List of chunk dictionaries with 'code', 'start_line', 'end_line'.
        """
        if len(code) <= self.max_chunk_size:
            return [{
                "code": code,
                "start_line": 1,
                "end_line": code.count("\n") + 1,
            }]

        lines = code.split("\n")
        chunks = []
        current_chunk_lines = []
        current_start = 1
        current_size = 0

        # Patterns that indicate good split points
        split_patterns = re.compile(
            r"^(def |class |function |func |fn |public |private |protected |"
            r"@app\.|@router\.|module |package )"
        )

        for i, line in enumerate(lines, 1):
            current_chunk_lines.append(line)
            current_size += len(line) + 1  # +1 for newline

            # Check if we should split
            if current_size >= self.max_chunk_size:
                # Try to find a good split point (look back)
                split_idx = len(current_chunk_lines) - 1
                for j in range(len(current_chunk_lines) - 1, max(0, len(current_chunk_lines) - 20), -1):
                    if split_patterns.match(current_chunk_lines[j].strip()):
                        split_idx = j
                        break

                # Create chunk
                chunk_lines = current_chunk_lines[:split_idx]
                chunks.append({
                    "code": "\n".join(chunk_lines),
                    "start_line": current_start,
                    "end_line": current_start + len(chunk_lines) - 1,
                })

                # Start new chunk with overlap
                overlap_start = max(0, split_idx - self.overlap // 50)
                current_chunk_lines = current_chunk_lines[overlap_start:]
                current_start = current_start + overlap_start
                current_size = sum(len(l) + 1 for l in current_chunk_lines)

        # Don't forget the last chunk
        if current_chunk_lines:
            chunks.append({
                "code": "\n".join(current_chunk_lines),
                "start_line": current_start,
                "end_line": current_start + len(current_chunk_lines) - 1,
            })

        return chunks

    def extract_functions(self, code: str, language: str = "python") -> list[dict]:
        """
        Extract individual functions/methods from source code.
        
        This enables function-level vulnerability analysis, which is
        more precise than file-level analysis.
        
        Args:
            code: Source code string.
            language: Programming language.
            
        Returns:
            List of dicts with 'name', 'code', 'start_line', 'end_line'.
        """
        functions = []

        # Language-specific function patterns
        patterns = {
            "python": r"(?:^|\n)([ \t]*(?:async\s+)?def\s+(\w+)\s*\(.*?\).*?:.*?)(?=\n[ \t]*(?:(?:async\s+)?def\s|class\s)|\Z)",
            "javascript": r"(?:(?:async\s+)?function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:function|\(.*?\)\s*=>))",
            "java": r"(?:public|private|protected|static|\s)+[\w<>\[\]]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s]+)?\s*\{",
            "go": r"func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(",
            "rust": r"(?:pub\s+)?(?:async\s+)?fn\s+(\w+)",
            "c": r"(?:static\s+)?(?:inline\s+)?[\w*]+\s+(\w+)\s*\([^)]*\)\s*\{",
            "cpp": r"(?:static\s+)?(?:inline\s+)?(?:virtual\s+)?[\w*:]+\s+(\w+)\s*\([^)]*\)\s*(?:const\s*)?(?:override\s*)?\{",
        }

        pattern = patterns.get(language, patterns.get("python"))
        if not pattern:
            return functions

        lines = code.split("\n")
        for match in re.finditer(pattern, code, re.DOTALL):
            name = next((g for g in match.groups() if g), "unknown")
            start_pos = match.start()
            start_line = code[:start_pos].count("\n") + 1

            functions.append({
                "name": name,
                "code": match.group(0),
                "start_line": start_line,
                "end_line": start_line + match.group(0).count("\n"),
            })

        return functions

    def preprocess(
        self,
        code: str,
        filepath: str | None = None,
    ) -> dict:
        """
        Full preprocessing pipeline for a code file.
        
        Args:
            code: Raw source code.
            filepath: Optional file path.
            
        Returns:
            Dictionary with normalized code, detected language/frameworks,
            chunks, and functions.
        """
        normalized = self.normalize(code)
        language = self.detect_language(normalized, filepath)
        frameworks = self.detect_frameworks(normalized)
        chunks = self.chunk_code(normalized)
        functions = self.extract_functions(normalized, language)

        return {
            "code": normalized,
            "language": language,
            "frameworks": frameworks,
            "chunks": chunks,
            "functions": functions,
            "filepath": filepath,
            "line_count": normalized.count("\n"),
            "char_count": len(normalized),
        }
