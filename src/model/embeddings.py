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



class RotaryPositionalEmbedding(nn.Module):
    """
    Rotary Positional Embedding (RoPE) as described in RoFormer (Su et al.).

    RoPE applies positional information at the self-attention layer by rotating
    the query and key representations. This provides better extrapolation
    to longer sequence lengths than standard sinusoidal embeddings.
    """

    def __init__(self, d_model: int, max_len: int = 2048, base: int = 10000):
        super().__init__()
        self.d_model = d_model

        # RoPE is applied to each head independently, so we assume d_model
        # here is actually d_head (d_model // num_heads) in practice, but
        # for flexibility we create it for the full d_model dimension
        # and it will be broadcasted correctly if used per-head.
        # Actually, in standard implementation, RoPE is applied per-head.

        # Precompute frequencies
        inv_freq = 1.0 / (base ** (torch.arange(0, d_model, 2).float() / d_model))
        self.register_buffer("inv_freq", inv_freq)

        # Precompute the cos and sin cache up to max_len
        self.max_len = max_len
        self._build_cache(max_len)

    def _build_cache(self, seq_len: int):
        t = torch.arange(seq_len, device=self.inv_freq.device, dtype=self.inv_freq.dtype)
        freqs = torch.outer(t, self.inv_freq)
        # Different from paper: we use polar formulation
        emb = torch.cat((freqs, freqs), dim=-1)
        self.register_buffer("cos_cached", emb.cos()[None, None, :, :])
        self.register_buffer("sin_cached", emb.sin()[None, None, :, :])

    def forward(self, x: torch.Tensor, seq_len: int) -> tuple[torch.Tensor, torch.Tensor]:
        """
        Returns cos and sin for rotary embeddings.
        x: Input tensor, just for device and dtype.
        seq_len: Sequence length to get embeddings for.
        """
        if seq_len > self.max_len:
            self._build_cache(seq_len)
            self.max_len = seq_len

        return (
            self.cos_cached[:, :, :seq_len, ...].to(dtype=x.dtype),
            self.sin_cached[:, :, :seq_len, ...].to(dtype=x.dtype)
        )

def apply_rotary_pos_emb(q: torch.Tensor, k: torch.Tensor, cos: torch.Tensor, sin: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
    """
    Apply rotary positional embeddings to queries and keys.
    q, k: (batch_size, num_heads, seq_len, d_head)
    cos, sin: (1, 1, seq_len, d_head)
    """
    def rotate_half(x):
        x1, x2 = x[..., : x.shape[-1] // 2], x[..., x.shape[-1] // 2 :]
        return torch.cat((-x2, x1), dim=-1)

    q_embed = (q * cos) + (rotate_half(q) * sin)
    k_embed = (k * cos) + (rotate_half(k) * sin)
    return q_embed, k_embed


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

        # We now use RoPE at the attention layer, but we keep sinusoidal
        # or remove it. Let's keep it but make it optional, or just remove it.
        # The prompt says "Replace or supplement". Let's supplement by keeping it,
        # or replacing it. I'll replace it.

        self.use_rope = True
        if not self.use_rope:
            self.positional_encoding = SinusoidalPositionalEncoding(
                d_model=d_model, max_len=max_len, dropout=0.0
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

        # Add positional encoding if not using RoPE
        if not getattr(self, 'use_rope', False) and hasattr(self, 'positional_encoding'):
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
