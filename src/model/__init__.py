"""
BAYREUTHWING — Model Module
Core transformer architecture for code vulnerability detection.
"""

from .transformer import CodeTransformer
from .tokenizer import CodeTokenizer

__all__ = ["CodeTransformer", "CodeTokenizer"]
