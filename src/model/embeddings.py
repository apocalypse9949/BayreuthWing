"""
BAYREUTHWING — Embeddings Module

Implements positional encoding and token-type embeddings for the CodeTransformer.
Uses sinusoidal positional encoding (Vaswani et al.) combined with learned
token-type embeddings to give the model awareness of both position and
the syntactic role of each token.
"""

import math
import torch
import torch.nn as nn


class SinusoidalPositionalEncoding(nn.Module):
    """
    Sinusoidal positional encoding as described in 'Attention Is All You Need'.
    
    Generates fixed positional signals using sine and cosine functions at
    different frequencies, allowing the model to learn position-dependent
    patterns in code sequences.
    """

    def __init__(self, d_model: int, max_len: int = 2048, dropout: float = 0.1):
        """
        Args:
            d_model: Embedding dimension size.
            max_len: Maximum sequence length supported.
            dropout: Dropout probability applied after positional encoding.
        """
        super().__init__()
        self.dropout = nn.Dropout(p=dropout)

        # Precompute the positional encoding matrix
        pe = torch.zeros(max_len, d_model)
        position = torch.arange(0, max_len, dtype=torch.float).unsqueeze(1)
        div_term = torch.exp(
            torch.arange(0, d_model, 2).float() * (-math.log(10000.0) / d_model)
        )

        pe[:, 0::2] = torch.sin(position * div_term)
        pe[:, 1::2] = torch.cos(position * div_term)
        pe = pe.unsqueeze(0)  # Shape: (1, max_len, d_model)

        # Register as buffer (not a parameter, but moves with model to device)
        self.register_buffer("pe", pe)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Add positional encoding to input tensor.
        
        Args:
            x: Input tensor of shape (batch_size, seq_len, d_model)
            
        Returns:
            Positionally encoded tensor of same shape.
        """
        x = x + self.pe[:, : x.size(1), :]
        return self.dropout(x)


class TokenTypeEmbedding(nn.Module):
    """
    Learned token-type embeddings for code tokens.
    
    Each token in the input is assigned a type (keyword, identifier, literal,
    operator, etc.) and this module learns a dense representation for each type.
    This gives the transformer additional signal about the syntactic role of
    each token, which is critical for understanding code structure.
    
    Token Type IDs:
        0 — keyword (def, class, if, for, while, return, import, etc.)
        1 — identifier (variable names, function names, class names)
        2 — literal (string literals, numeric literals)
        3 — operator (+, -, *, /, =, ==, !=, <, >, etc.)
        4 — delimiter (parentheses, brackets, braces, commas, semicolons)
        5 — comment (single-line and multi-line comments)
        6 — string (string content, distinct from string delimiters)
        7 — number (numeric values)
        8 — whitespace (spaces, tabs, newlines)
        9 — unknown (unrecognized tokens)
    """

    NUM_TOKEN_TYPES = 10

    def __init__(self, d_model: int):
        """
        Args:
            d_model: Embedding dimension size (must match other embeddings).
        """
        super().__init__()
        self.embedding = nn.Embedding(self.NUM_TOKEN_TYPES, d_model)
        self._init_weights()

    def _init_weights(self):
        """Initialize embeddings with small random values."""
        nn.init.normal_(self.embedding.weight, mean=0.0, std=0.02)

    def forward(self, token_type_ids: torch.Tensor) -> torch.Tensor:
        """
        Look up embeddings for given token type IDs.
        
        Args:
            token_type_ids: Integer tensor of shape (batch_size, seq_len)
                           with values in [0, NUM_TOKEN_TYPES).
                           
        Returns:
            Token type embeddings of shape (batch_size, seq_len, d_model).
        """
        return self.embedding(token_type_ids)


class CodeEmbedding(nn.Module):
    """
    Complete embedding layer for the CodeTransformer.
    
    Combines three embedding signals:
    1. Token embeddings — learned dense representations for each vocabulary token
    2. Positional encoding — sinusoidal position signals
    3. Token-type embeddings — learned representations for syntactic roles
    
    The final embedding is the sum of all three, followed by layer normalization
    and dropout for regularization.
    """

    def __init__(
        self,
        vocab_size: int = 32000,
        d_model: int = 512,
        max_len: int = 2048,
        dropout: float = 0.1,
        padding_idx: int = 0,
    ):
        """
        Args:
            vocab_size: Size of the token vocabulary.
            d_model: Embedding dimension size.
            max_len: Maximum sequence length.
            dropout: Dropout probability.
            padding_idx: Index of the padding token (embeddings zeroed out).
        """
        super().__init__()

        self.d_model = d_model

        # Token embedding lookup
        self.token_embedding = nn.Embedding(
            vocab_size, d_model, padding_idx=padding_idx
        )

        # Positional encoding (sinusoidal, fixed)
        self.positional_encoding = SinusoidalPositionalEncoding(
            d_model=d_model, max_len=max_len, dropout=0.0  # dropout applied later
        )

        # Token type embedding (learned)
        self.token_type_embedding = TokenTypeEmbedding(d_model=d_model)

        # Normalization and dropout
        self.layer_norm = nn.LayerNorm(d_model, eps=1e-6)
        self.dropout = nn.Dropout(p=dropout)

        # Scale factor for token embeddings
        self.scale = math.sqrt(d_model)

        self._init_weights()

    def _init_weights(self):
        """Initialize token embedding weights."""
        nn.init.normal_(self.token_embedding.weight, mean=0.0, std=0.02)
        # Zero out padding embedding
        if self.token_embedding.padding_idx is not None:
            with torch.no_grad():
                self.token_embedding.weight[self.token_embedding.padding_idx].fill_(0)

    def forward(
        self,
        input_ids: torch.Tensor,
        token_type_ids: torch.Tensor | None = None,
    ) -> torch.Tensor:
        """
        Compute combined embeddings for input tokens.
        
        Args:
            input_ids: Token IDs of shape (batch_size, seq_len).
            token_type_ids: Optional token type IDs of shape (batch_size, seq_len).
                           If None, defaults to all zeros (unknown type).
                           
        Returns:
            Combined embeddings of shape (batch_size, seq_len, d_model).
        """
        seq_len = input_ids.size(1)

        # Token embeddings (scaled)
        x = self.token_embedding(input_ids) * self.scale

        # Add positional encoding
        x = self.positional_encoding(x)

        # Add token type embeddings if provided
        if token_type_ids is not None:
            x = x + self.token_type_embedding(token_type_ids)
        else:
            # Default: all tokens treated as 'unknown' type (9)
            default_types = torch.full(
                (input_ids.size(0), seq_len),
                fill_value=9,
                dtype=torch.long,
                device=input_ids.device,
            )
            x = x + self.token_type_embedding(default_types)

        # Normalize and apply dropout
        x = self.layer_norm(x)
        x = self.dropout(x)

        return x
