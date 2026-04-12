"""
BAYREUTHWING — Attention Module

Implements multi-head self-attention and a specialized Vulnerability Attention
mechanism. The vulnerability attention head learns to focus on security-critical
code patterns (e.g., user input flowing into dangerous sinks, crypto misuse,
unsanitized data handling).
"""

import math
import torch
import torch.nn as nn
import torch.nn.functional as F


class MultiHeadSelfAttention(nn.Module):
    """
    Standard multi-head self-attention mechanism.
    
    Splits the input into multiple attention heads, computes scaled dot-product
    attention independently for each head, then concatenates and projects the
    results. This allows the model to jointly attend to information from
    different representation subspaces.
    """

    def __init__(self, d_model: int = 512, num_heads: int = 8, dropout: float = 0.1):
        """
        Args:
            d_model: Model dimension (must be divisible by num_heads).
            num_heads: Number of parallel attention heads.
            dropout: Dropout probability for attention weights.
        """
        super().__init__()
        assert d_model % num_heads == 0, "d_model must be divisible by num_heads"

        self.d_model = d_model
        self.num_heads = num_heads
        self.d_k = d_model // num_heads

        # Linear projections for Q, K, V and output
        self.W_q = nn.Linear(d_model, d_model, bias=False)
        self.W_k = nn.Linear(d_model, d_model, bias=False)
        self.W_v = nn.Linear(d_model, d_model, bias=False)
        self.W_o = nn.Linear(d_model, d_model, bias=False)

        self.dropout = nn.Dropout(p=dropout)
        self.scale = math.sqrt(self.d_k)

        self._init_weights()

    def _init_weights(self):
        """Xavier uniform initialization for attention projections."""
        for module in [self.W_q, self.W_k, self.W_v, self.W_o]:
            nn.init.xavier_uniform_(module.weight)

    def forward(
        self,
        x: torch.Tensor,
        mask: torch.Tensor | None = None,
        return_attention: bool = False,
    ) -> tuple[torch.Tensor, torch.Tensor | None]:
        """
        Compute multi-head self-attention.
        
        Args:
            x: Input tensor of shape (batch_size, seq_len, d_model).
            mask: Optional attention mask of shape (batch_size, 1, 1, seq_len)
                  or (batch_size, 1, seq_len, seq_len). Positions with True/1
                  are masked (not attended to).
            return_attention: If True, also return the attention weight matrix.
            
        Returns:
            Tuple of (output, attention_weights).
            output: Shape (batch_size, seq_len, d_model).
            attention_weights: Shape (batch_size, num_heads, seq_len, seq_len) or None.
        """
        batch_size, seq_len, _ = x.shape

        # Project to Q, K, V
        Q = self.W_q(x)
        K = self.W_k(x)
        V = self.W_v(x)

        # Reshape to (batch_size, num_heads, seq_len, d_k)
        Q = Q.view(batch_size, seq_len, self.num_heads, self.d_k).transpose(1, 2)
        K = K.view(batch_size, seq_len, self.num_heads, self.d_k).transpose(1, 2)
        V = V.view(batch_size, seq_len, self.num_heads, self.d_k).transpose(1, 2)

        # Scaled dot-product attention
        scores = torch.matmul(Q, K.transpose(-2, -1)) / self.scale

        # Apply mask if provided
        if mask is not None:
            scores = scores.masked_fill(mask == 1, float("-inf"))

        attention_weights = F.softmax(scores, dim=-1)
        attention_weights = self.dropout(attention_weights)

        # Weighted sum of values
        context = torch.matmul(attention_weights, V)

        # Concatenate heads and project
        context = (
            context.transpose(1, 2)
            .contiguous()
            .view(batch_size, seq_len, self.d_model)
        )
        output = self.W_o(context)

        if return_attention:
            return output, attention_weights
        return output, None


class VulnerabilityAttention(nn.Module):
    """
    Specialized attention mechanism for vulnerability detection.
    
    This module learns to focus on security-critical code patterns by maintaining
    a set of learned 'vulnerability query vectors' — one per vulnerability class.
    Each query vector learns to attend to the code patterns most indicative of
    its corresponding vulnerability type.
    
    Architecture:
    - N vulnerability query vectors (one per class) attend over the code sequence
    - Produces a vulnerability-aware representation for each class
    - Cross-attention: vulnerability queries attend to code tokens
    
    This gives the model an explicit mechanism to specialize attention patterns
    for different vulnerability types, rather than relying solely on the
    classification head to disentangle them.
    """

    def __init__(
        self,
        d_model: int = 512,
        num_vuln_classes: int = 11,
        num_heads: int = 4,
        dropout: float = 0.1,
    ):
        """
        Args:
            d_model: Model dimension.
            num_vuln_classes: Number of vulnerability classes to detect.
            num_heads: Number of attention heads for cross-attention.
            dropout: Dropout probability.
        """
        super().__init__()

        self.d_model = d_model
        self.num_vuln_classes = num_vuln_classes
        self.num_heads = num_heads
        self.d_k = d_model // num_heads

        # Learned vulnerability query vectors
        # Each vector represents a "question": "Is this vulnerability present?"
        self.vuln_queries = nn.Parameter(
            torch.randn(1, num_vuln_classes, d_model) * 0.02
        )

        # Cross-attention projections
        self.W_q = nn.Linear(d_model, d_model, bias=False)
        self.W_k = nn.Linear(d_model, d_model, bias=False)
        self.W_v = nn.Linear(d_model, d_model, bias=False)
        self.W_o = nn.Linear(d_model, d_model, bias=False)

        # Gating mechanism — learns how much vulnerability attention to blend in
        self.gate = nn.Sequential(
            nn.Linear(d_model * 2, d_model),
            nn.Sigmoid(),
        )

        self.layer_norm = nn.LayerNorm(d_model, eps=1e-6)
        self.dropout = nn.Dropout(p=dropout)
        self.scale = math.sqrt(self.d_k)

        self._init_weights()

    def _init_weights(self):
        """Initialize weights."""
        for module in [self.W_q, self.W_k, self.W_v, self.W_o]:
            nn.init.xavier_uniform_(module.weight)

    def forward(
        self,
        code_repr: torch.Tensor,
        mask: torch.Tensor | None = None,
        return_attention: bool = False,
    ) -> tuple[torch.Tensor, torch.Tensor | None]:
        """
        Apply vulnerability-focused cross-attention.
        
        Args:
            code_repr: Code representation from encoder, shape (batch, seq_len, d_model).
            mask: Optional padding mask for code tokens.
            return_attention: If True, return attention weights for interpretability.
            
        Returns:
            Tuple of:
            - vuln_repr: Vulnerability representations, shape (batch, num_vuln_classes, d_model)
            - attention_weights: Optional, shape (batch, num_heads, num_vuln_classes, seq_len)
        """
        batch_size = code_repr.size(0)

        # Expand vulnerability queries for batch
        queries = self.vuln_queries.expand(batch_size, -1, -1)

        # Project
        Q = self.W_q(queries)  # (batch, num_vuln, d_model)
        K = self.W_k(code_repr)  # (batch, seq_len, d_model)
        V = self.W_v(code_repr)  # (batch, seq_len, d_model)

        # Reshape for multi-head attention
        Q = Q.view(batch_size, self.num_vuln_classes, self.num_heads, self.d_k).transpose(1, 2)
        K = K.view(batch_size, -1, self.num_heads, self.d_k).transpose(1, 2)
        V = V.view(batch_size, -1, self.num_heads, self.d_k).transpose(1, 2)

        # Cross-attention scores
        scores = torch.matmul(Q, K.transpose(-2, -1)) / self.scale

        # Apply mask if provided (mask padding tokens)
        if mask is not None:
            # mask shape: (batch, 1, 1, seq_len)
            scores = scores.masked_fill(mask == 1, float("-inf"))

        attention_weights = F.softmax(scores, dim=-1)
        attention_weights = self.dropout(attention_weights)

        # Weighted sum of code representations
        context = torch.matmul(attention_weights, V)

        # Concatenate heads
        context = (
            context.transpose(1, 2)
            .contiguous()
            .view(batch_size, self.num_vuln_classes, self.d_model)
        )
        vuln_repr = self.W_o(context)

        # Gated residual connection with original queries
        gate_input = torch.cat([vuln_repr, queries], dim=-1)
        gate_values = self.gate(gate_input)
        vuln_repr = gate_values * vuln_repr + (1 - gate_values) * queries

        vuln_repr = self.layer_norm(vuln_repr)

        if return_attention:
            return vuln_repr, attention_weights
        return vuln_repr, None


class FeedForwardNetwork(nn.Module):
    """
    Position-wise feed-forward network with GELU activation.
    
    Two linear transformations with a GELU activation in between:
        FFN(x) = W2 * GELU(W1 * x + b1) + b2
    
    The intermediate dimension is typically 4x the model dimension,
    allowing the network to learn complex non-linear transformations.
    """

    def __init__(
        self,
        d_model: int = 512,
        d_ff: int = 2048,
        dropout: float = 0.1,
        activation: str = "gelu",
    ):
        """
        Args:
            d_model: Model dimension (input and output size).
            d_ff: Intermediate feed-forward dimension.
            dropout: Dropout probability.
            activation: Activation function ('gelu' or 'relu').
        """
        super().__init__()

        self.linear1 = nn.Linear(d_model, d_ff)
        self.linear2 = nn.Linear(d_ff, d_model)
        self.dropout = nn.Dropout(p=dropout)

        if activation == "gelu":
            self.activation = nn.GELU()
        elif activation == "relu":
            self.activation = nn.ReLU()
        else:
            raise ValueError(f"Unsupported activation: {activation}")

        self._init_weights()

    def _init_weights(self):
        """Kaiming initialization for feed-forward layers."""
        nn.init.kaiming_normal_(self.linear1.weight, nonlinearity="relu")
        nn.init.zeros_(self.linear1.bias)
        nn.init.xavier_uniform_(self.linear2.weight)
        nn.init.zeros_(self.linear2.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Apply feed-forward transformation.
        
        Args:
            x: Input tensor of shape (batch_size, seq_len, d_model).
            
        Returns:
            Output tensor of same shape.
        """
        x = self.linear1(x)
        x = self.activation(x)
        x = self.dropout(x)
        x = self.linear2(x)
        x = self.dropout(x)
        return x
