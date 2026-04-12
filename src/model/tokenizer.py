"""
BAYREUTHWING — Code Tokenizer

Custom BPE-inspired tokenizer designed for source code. Unlike natural language
tokenizers, this tokenizer understands code structure: it splits on code-specific
boundaries (operators, delimiters), preserves string literals and identifiers,
and classifies each token by its syntactic role.

The tokenizer maintains a vocabulary of 32,000 tokens built from common code
patterns across multiple programming languages.
"""

import re
from typing import Optional
from collections import OrderedDict


# ─── Token type constants ───────────────────────────────────────────
TOKEN_TYPE_KEYWORD = 0
TOKEN_TYPE_IDENTIFIER = 1
TOKEN_TYPE_LITERAL = 2
TOKEN_TYPE_OPERATOR = 3
TOKEN_TYPE_DELIMITER = 4
TOKEN_TYPE_COMMENT = 5
TOKEN_TYPE_STRING = 6
TOKEN_TYPE_NUMBER = 7
TOKEN_TYPE_WHITESPACE = 8
TOKEN_TYPE_UNKNOWN = 9

TOKEN_TYPE_NAMES = {
    TOKEN_TYPE_KEYWORD: "keyword",
    TOKEN_TYPE_IDENTIFIER: "identifier",
    TOKEN_TYPE_LITERAL: "literal",
    TOKEN_TYPE_OPERATOR: "operator",
    TOKEN_TYPE_DELIMITER: "delimiter",
    TOKEN_TYPE_COMMENT: "comment",
    TOKEN_TYPE_STRING: "string",
    TOKEN_TYPE_NUMBER: "number",
    TOKEN_TYPE_WHITESPACE: "whitespace",
    TOKEN_TYPE_UNKNOWN: "unknown",
}


# ─── Language keyword sets ──────────────────────────────────────────
PYTHON_KEYWORDS = {
    "False", "None", "True", "and", "as", "assert", "async", "await",
    "break", "class", "continue", "def", "del", "elif", "else", "except",
    "finally", "for", "from", "global", "if", "import", "in", "is",
    "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
    "while", "with", "yield",
}

JAVASCRIPT_KEYWORDS = {
    "abstract", "arguments", "await", "boolean", "break", "byte", "case",
    "catch", "char", "class", "const", "continue", "debugger", "default",
    "delete", "do", "double", "else", "enum", "eval", "export", "extends",
    "false", "final", "finally", "float", "for", "function", "goto", "if",
    "implements", "import", "in", "instanceof", "int", "interface", "let",
    "long", "native", "new", "null", "package", "private", "protected",
    "public", "return", "short", "static", "super", "switch", "synchronized",
    "this", "throw", "throws", "transient", "true", "try", "typeof", "var",
    "void", "volatile", "while", "with", "yield",
}

JAVA_KEYWORDS = {
    "abstract", "assert", "boolean", "break", "byte", "case", "catch",
    "char", "class", "const", "continue", "default", "do", "double",
    "else", "enum", "extends", "false", "final", "finally", "float",
    "for", "goto", "if", "implements", "import", "instanceof", "int",
    "interface", "long", "native", "new", "null", "package", "private",
    "protected", "public", "return", "short", "static", "strictfp",
    "super", "switch", "synchronized", "this", "throw", "throws",
    "transient", "true", "try", "void", "volatile", "while",
}

C_CPP_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default",
    "do", "double", "else", "enum", "extern", "float", "for", "goto",
    "if", "inline", "int", "long", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch", "typedef",
    "union", "unsigned", "void", "volatile", "while",
    # C++ additions
    "alignas", "alignof", "bool", "catch", "class", "constexpr",
    "decltype", "delete", "dynamic_cast", "explicit", "export", "false",
    "friend", "mutable", "namespace", "new", "noexcept", "nullptr",
    "operator", "private", "protected", "public", "reinterpret_cast",
    "static_assert", "static_cast", "template", "this", "throw", "true",
    "try", "typeid", "typename", "using", "virtual",
}

GO_KEYWORDS = {
    "break", "case", "chan", "const", "continue", "default", "defer",
    "else", "fallthrough", "for", "func", "go", "goto", "if", "import",
    "interface", "map", "package", "range", "return", "select", "struct",
    "switch", "type", "var",
}

RUST_KEYWORDS = {
    "as", "async", "await", "break", "const", "continue", "crate", "dyn",
    "else", "enum", "extern", "false", "fn", "for", "if", "impl", "in",
    "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type",
    "unsafe", "use", "where", "while",
}

PHP_KEYWORDS = {
    "abstract", "and", "array", "as", "break", "callable", "case", "catch",
    "class", "clone", "const", "continue", "declare", "default", "die", "do",
    "echo", "else", "elseif", "empty", "enddeclare", "endfor", "endforeach",
    "endif", "endswitch", "endwhile", "eval", "exit", "extends", "false",
    "final", "finally", "fn", "for", "foreach", "function", "global", "goto",
    "if", "implements", "include", "include_once", "instanceof", "insteadof",
    "interface", "isset", "list", "match", "namespace", "new", "null", "or",
    "print", "private", "protected", "public", "readonly", "require",
    "require_once", "return", "static", "switch", "throw", "trait", "true",
    "try", "unset", "use", "var", "while", "xor", "yield",
}

RUBY_KEYWORDS = {
    "BEGIN", "END", "alias", "and", "begin", "break", "case", "class",
    "def", "defined?", "do", "else", "elsif", "end", "ensure", "false",
    "for", "if", "in", "module", "next", "nil", "not", "or", "redo",
    "rescue", "retry", "return", "self", "super", "then", "true",
    "undef", "unless", "until", "when", "while", "yield",
}

ALL_KEYWORDS = (
    PYTHON_KEYWORDS
    | JAVASCRIPT_KEYWORDS
    | JAVA_KEYWORDS
    | C_CPP_KEYWORDS
    | GO_KEYWORDS
    | RUST_KEYWORDS
    | PHP_KEYWORDS
    | RUBY_KEYWORDS
)

# Security-sensitive functions/patterns that get special tokens
SECURITY_SENSITIVE = {
    "eval", "exec", "system", "popen", "subprocess", "os.system",
    "os.popen", "pickle.loads", "yaml.load", "marshal.loads",
    "input", "raw_input", "scanf", "gets", "strcpy", "strcat",
    "sprintf", "printf", "fprintf", "mysql_query", "query",
    "execute", "cursor", "innerHTML", "document.write",
    "dangerouslySetInnerHTML", "child_process", "shell_exec",
    "passthru", "proc_open", "assert", "unserialize",
    "deserialize", "fromJson", "readFile", "writeFile",
    "open", "chmod", "chown", "request", "fetch",
    "XMLHttpRequest", "crypto", "md5", "sha1", "rand",
    "random", "Math.random", "SECRET", "PASSWORD", "API_KEY",
    "TOKEN", "PRIVATE_KEY", "credentials",
}


# ─── Regex patterns for tokenization ───────────────────────────────
CODE_TOKEN_PATTERN = re.compile(
    r"""
    (?P<string>\"\"\"[\s\S]*?\"\"\"|\'\'\'[\s\S]*?\'\'\'|  # Triple-quoted strings
                \"(?:[^\"\\]|\\.)*\"|                        # Double-quoted strings
                \'(?:[^\'\\]|\\.)*\')                        # Single-quoted strings
    |(?P<comment>//.*?$|                                     # Single-line comment (C-style)
                \#.*?$|                                       # Single-line comment (Python)
                /\*[\s\S]*?\*/)                               # Block comment
    |(?P<number>0[xX][0-9a-fA-F]+|                          # Hex numbers
               0[bB][01]+|                                    # Binary numbers
               0[oO][0-7]+|                                   # Octal numbers
               \d+\.\d*(?:[eE][+-]?\d+)?|                    # Float numbers
               \d+(?:[eE][+-]?\d+)?|                         # Integer/scientific
               \.\d+(?:[eE][+-]?\d+)?)                       # Decimal starting with dot
    |(?P<operator>[+\-*/%&|^~<>!=]=?|                       # Operators
                  <<|>>|&&|\|\||                              # Shift and logical
                  \+\+|--|                                     # Increment/decrement
                  ->|=>|::|\.\.\.|                            # Arrow, fat arrow, spread
                  \?\.|                                        # Optional chaining
                  [?:])                                        # Ternary
    |(?P<delimiter>[(){}\[\];,\.@])                          # Delimiters
    |(?P<identifier>[a-zA-Z_$][a-zA-Z0-9_$]*)              # Identifiers
    |(?P<whitespace>\s+)                                     # Whitespace
    |(?P<unknown>.)                                           # Everything else
    """,
    re.MULTILINE | re.VERBOSE,
)


class CodeTokenizer:
    """
    Code-aware tokenizer for the CodeTransformer model.
    
    Features:
    - Language-aware keyword recognition
    - Security-sensitive function detection
    - BPE-inspired subword splitting for rare identifiers
    - Token type classification
    - Special tokens: [PAD], [UNK], [CLS], [SEP], [VULN], [SAFE]
    """

    # Special token IDs
    PAD_TOKEN = "[PAD]"
    UNK_TOKEN = "[UNK]"
    CLS_TOKEN = "[CLS]"
    SEP_TOKEN = "[SEP]"
    VULN_TOKEN = "[VULN]"
    SAFE_TOKEN = "[SAFE]"

    SPECIAL_TOKENS = [PAD_TOKEN, UNK_TOKEN, CLS_TOKEN, SEP_TOKEN, VULN_TOKEN, SAFE_TOKEN]

    def __init__(self, vocab_size: int = 32000, max_length: int = 2048):
        """
        Initialize the tokenizer.
        
        Args:
            vocab_size: Maximum vocabulary size.
            max_length: Maximum sequence length (tokens beyond this are truncated).
        """
        self.vocab_size = vocab_size
        self.max_length = max_length

        # Build vocabulary
        self.token_to_id: dict[str, int] = OrderedDict()
        self.id_to_token: dict[int, str] = {}
        self._build_vocabulary()

    def _build_vocabulary(self):
        """
        Build the token vocabulary from special tokens, keywords,
        security-sensitive patterns, common code tokens, and character-level
        fallback tokens.
        """
        idx = 0

        # 1. Special tokens
        for token in self.SPECIAL_TOKENS:
            self.token_to_id[token] = idx
            self.id_to_token[idx] = token
            idx += 1

        # 2. All language keywords
        for keyword in sorted(ALL_KEYWORDS):
            if keyword not in self.token_to_id:
                self.token_to_id[keyword] = idx
                self.id_to_token[idx] = keyword
                idx += 1

        # 3. Security-sensitive tokens (special handling)
        for token in sorted(SECURITY_SENSITIVE):
            if token not in self.token_to_id:
                self.token_to_id[token] = idx
                self.id_to_token[idx] = token
                idx += 1

        # 4. Common operators and delimiters
        common_tokens = [
            "+", "-", "*", "/", "%", "=", "==", "!=", "<", ">", "<=", ">=",
            "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=",
            "&&", "||", "!", "&", "|", "^", "~", "<<", ">>",
            "(", ")", "{", "}", "[", "]", ";", ",", ".", ":", "::",
            "->", "=>", "...", "?.", "?", "@", "#",
            "++", "--", "**",
            # Common string tokens
            "\\n", "\\t", "\\r", "\\\\", '\\"', "\\'",
            # Common type annotations
            "int", "str", "float", "bool", "list", "dict", "tuple", "set",
            "string", "number", "boolean", "object", "any", "void",
            "null", "undefined", "None", "true", "false", "True", "False",
        ]
        for token in common_tokens:
            if token not in self.token_to_id:
                self.token_to_id[token] = idx
                self.id_to_token[idx] = token
                idx += 1

        # 5. Common programming identifiers and patterns
        common_identifiers = [
            "self", "this", "cls", "args", "kwargs", "init", "__init__",
            "main", "__main__", "print", "len", "range", "type", "isinstance",
            "append", "extend", "insert", "remove", "pop", "get", "set",
            "keys", "values", "items", "update", "format", "join", "split",
            "strip", "replace", "lower", "upper", "find", "index", "count",
            "sort", "sorted", "filter", "map", "reduce", "zip", "enumerate",
            "read", "write", "close", "flush", "seek",
            "connect", "send", "recv", "bind", "listen", "accept",
            "encode", "decode", "encrypt", "decrypt", "hash", "verify",
            "login", "logout", "authenticate", "authorize",
            "select", "insert", "update", "delete", "create", "drop",
            "request", "response", "session", "cookie", "header",
            "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS",
            "http", "https", "ftp", "ssh", "tcp", "udp",
            "localhost", "127.0.0.1", "0.0.0.0",
            "root", "admin", "user", "password", "username",
            "config", "settings", "env", "environment",
            "test", "mock", "assert", "expect", "describe", "it",
            "log", "debug", "info", "warn", "error", "fatal",
            "try", "catch", "throw", "raise", "except", "finally",
            "async", "await", "promise", "callback", "then",
            "export", "module", "require", "include",
            "public", "private", "protected", "static", "final",
            "class", "interface", "abstract", "extends", "implements",
            "package", "import", "from",
            "def", "func", "fn", "function", "method",
            "var", "let", "const", "val", "mut",
            "if", "else", "elif", "elsif", "switch", "case", "match",
            "for", "while", "do", "loop", "each", "foreach",
            "break", "continue", "return", "yield", "pass",
            "new", "delete", "malloc", "free", "alloc", "dealloc",
            "sizeof", "typeof", "instanceof",
            "TODO", "FIXME", "HACK", "XXX", "BUG", "NOTE",
            "FILE", "LINE", "FUNCTION",
            "stdin", "stdout", "stderr",
            "buffer", "Buffer", "array", "Array", "String",
            "JSON", "XML", "HTML", "CSS", "SQL",
            "Exception", "Error", "RuntimeError", "ValueError",
            "TypeError", "KeyError", "IndexError", "IOError",
            "NullPointerException", "IllegalArgumentException",
        ]
        for token in common_identifiers:
            if token not in self.token_to_id:
                self.token_to_id[token] = idx
                self.id_to_token[idx] = token
                idx += 1

        # 6. Single characters (ASCII printable) for subword fallback
        for c in range(32, 127):
            char = chr(c)
            if char not in self.token_to_id:
                self.token_to_id[char] = idx
                self.id_to_token[idx] = char
                idx += 1

        # 7. Common subword fragments (BPE-inspired)
        subwords = [
            "##ing", "##tion", "##er", "##ed", "##ly", "##ment",
            "##ness", "##able", "##ible", "##ful", "##less",
            "##ize", "##ise", "##ous", "##ive", "##al",
            "re##", "un##", "pre##", "dis##", "over##",
            "get_", "set_", "is_", "has_", "can_", "do_",
            "_id", "_name", "_type", "_size", "_count", "_list",
            "_data", "_info", "_config", "_path", "_file", "_dir",
            "_key", "_value", "_index", "_error", "_result",
            "_input", "_output", "_handler", "_callback",
            "_request", "_response", "_session", "_token",
            "_url", "_host", "_port", "_user", "_pass",
        ]
        for token in subwords:
            if token not in self.token_to_id:
                self.token_to_id[token] = idx
                self.id_to_token[idx] = token
                idx += 1

        # Pad remaining with placeholder tokens if needed
        while idx < self.vocab_size:
            placeholder = f"[UNUSED_{idx}]"
            self.token_to_id[placeholder] = idx
            self.id_to_token[idx] = placeholder
            idx += 1

    def _classify_token(self, token: str, match_group: str) -> int:
        """
        Classify a token into its syntactic type.
        
        Args:
            token: The token string.
            match_group: The regex group name that matched.
            
        Returns:
            Token type ID.
        """
        if match_group == "comment":
            return TOKEN_TYPE_COMMENT
        elif match_group == "string":
            return TOKEN_TYPE_STRING
        elif match_group == "number":
            return TOKEN_TYPE_NUMBER
        elif match_group == "operator":
            return TOKEN_TYPE_OPERATOR
        elif match_group == "delimiter":
            return TOKEN_TYPE_DELIMITER
        elif match_group == "whitespace":
            return TOKEN_TYPE_WHITESPACE
        elif match_group == "identifier":
            if token in ALL_KEYWORDS:
                return TOKEN_TYPE_KEYWORD
            else:
                return TOKEN_TYPE_IDENTIFIER
        else:
            return TOKEN_TYPE_UNKNOWN

    def tokenize(self, code: str) -> list[dict]:
        """
        Tokenize source code into a list of token dictionaries.
        
        Each token dict contains:
        - 'token': The token string
        - 'type': Token type ID
        - 'type_name': Human-readable type name
        - 'is_security_sensitive': Whether this is a security-sensitive token
        
        Args:
            code: Source code string.
            
        Returns:
            List of token dictionaries.
        """
        tokens = []

        for match in CODE_TOKEN_PATTERN.finditer(code):
            # Find which group matched
            for group_name in [
                "string", "comment", "number", "operator",
                "delimiter", "identifier", "whitespace", "unknown",
            ]:
                value = match.group(group_name)
                if value is not None:
                    token_type = self._classify_token(value, group_name)

                    # Skip whitespace tokens (they waste sequence length)
                    if token_type == TOKEN_TYPE_WHITESPACE:
                        break

                    tokens.append({
                        "token": value,
                        "type": token_type,
                        "type_name": TOKEN_TYPE_NAMES[token_type],
                        "is_security_sensitive": value in SECURITY_SENSITIVE,
                    })
                    break

        return tokens

    def encode(
        self,
        code: str,
        max_length: Optional[int] = None,
        add_special_tokens: bool = True,
        padding: bool = True,
    ) -> dict[str, list[int]]:
        """
        Encode source code into model-ready input IDs and type IDs.
        
        Args:
            code: Source code string.
            max_length: Override default max sequence length.
            add_special_tokens: If True, prepend [CLS] and append [SEP].
            padding: If True, pad to max_length.
            
        Returns:
            Dictionary with:
            - 'input_ids': List of token IDs
            - 'token_type_ids': List of token type IDs
            - 'attention_mask': List of 0/1 indicating real vs padding tokens
        """
        max_len = max_length or self.max_length
        tokens = self.tokenize(code)

        # Reserve space for special tokens
        if add_special_tokens:
            max_tokens = max_len - 2
        else:
            max_tokens = max_len

        # Truncate if needed
        tokens = tokens[:max_tokens]

        # Convert to IDs
        input_ids = []
        token_type_ids = []

        if add_special_tokens:
            input_ids.append(self.token_to_id[self.CLS_TOKEN])
            token_type_ids.append(TOKEN_TYPE_UNKNOWN)

        for token_info in tokens:
            token_str = token_info["token"]
            token_type = token_info["type"]

            if token_str in self.token_to_id:
                input_ids.append(self.token_to_id[token_str])
            else:
                # Subword splitting for unknown tokens
                sub_ids = self._subword_encode(token_str)
                input_ids.extend(sub_ids)
                token_type_ids.extend([token_type] * (len(sub_ids) - 1))

            token_type_ids.append(token_type)

        if add_special_tokens:
            input_ids.append(self.token_to_id[self.SEP_TOKEN])
            token_type_ids.append(TOKEN_TYPE_UNKNOWN)

        # Truncate again in case subword splitting expanded beyond limit
        input_ids = input_ids[:max_len]
        token_type_ids = token_type_ids[:max_len]

        # Create attention mask (1 = real token, 0 = padding)
        attention_mask = [1] * len(input_ids)

        # Pad if needed
        if padding:
            pad_length = max_len - len(input_ids)
            input_ids.extend([self.token_to_id[self.PAD_TOKEN]] * pad_length)
            token_type_ids.extend([TOKEN_TYPE_UNKNOWN] * pad_length)
            attention_mask.extend([0] * pad_length)

        return {
            "input_ids": input_ids,
            "token_type_ids": token_type_ids,
            "attention_mask": attention_mask,
        }

    def _subword_encode(self, token: str) -> list[int]:
        """
        Encode an unknown token using character-level fallback.
        
        Args:
            token: Unknown token string.
            
        Returns:
            List of token IDs (character-level).
        """
        ids = []
        for char in token:
            if char in self.token_to_id:
                ids.append(self.token_to_id[char])
            else:
                ids.append(self.token_to_id[self.UNK_TOKEN])
        return ids if ids else [self.token_to_id[self.UNK_TOKEN]]

    def decode(self, token_ids: list[int]) -> str:
        """
        Decode token IDs back to a string.
        
        Args:
            token_ids: List of token IDs.
            
        Returns:
            Decoded string (best-effort reconstruction).
        """
        tokens = []
        for tid in token_ids:
            token = self.id_to_token.get(tid, self.UNK_TOKEN)
            if token in self.SPECIAL_TOKENS:
                continue
            tokens.append(token)
        return " ".join(tokens)

    def vocab_info(self) -> dict:
        """Return vocabulary statistics."""
        return {
            "vocab_size": len(self.token_to_id),
            "max_length": self.max_length,
            "num_keywords": len(ALL_KEYWORDS),
            "num_security_tokens": len(SECURITY_SENSITIVE),
            "special_tokens": self.SPECIAL_TOKENS,
        }
