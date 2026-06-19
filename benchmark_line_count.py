import time
import re
from src.scanner.analyzer import CodeAnalyzer

# Create a huge dummy file
code = "def test():\n" * 100000 + "import pickle\n" * 1000

analyzer = CodeAnalyzer()

# Monkey patch for new
def fast_analyze_imports(self, code: str, language: str) -> list[dict]:
    imports = []
    if language == "python":
        patterns = [
            (r"import\s+(pickle|shelve|marshal)", "Unsafe serialization library imported"),
        ]
    else:
        patterns = []

    for pattern, message in patterns:
        last_idx = 0
        current_line = 1
        for match in re.finditer(pattern, code):
            current_line += code.count("\n", last_idx, match.start())
            last_idx = match.start()
            imports.append({
                "line": current_line,
                "import": match.group(0),
                "message": message,
            })

    return imports

CodeAnalyzer._fast_analyze_imports = fast_analyze_imports

start = time.time()
analyzer._analyze_imports(code, "python")
end = time.time()
print(f"Time for old _analyze_imports (100k lines): {end - start:.4f} seconds")

start = time.time()
analyzer._fast_analyze_imports(code, "python")
end = time.time()
print(f"Time for fast _analyze_imports (100k lines): {end - start:.4f} seconds")
