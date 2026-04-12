"""
BAYREUTHWING — CodeTransformer Architecture

The core neural network model for code vulnerability detection. Implements a
transformer encoder with specialized vulnerability attention, producing
multi-label vulnerability predictions with confidence scores.

Architecture Overview:
    Input IDs → CodeEmbedding → [TransformerEncoderLayer × N] →
    VulnerabilityAttention → ClassificationHead → Vulnerability Predictions

The model processes tokenized source code and produces per-vulnerability-class
probability scores, enabling detection of multiple vulnerability types
simultaneously in a single code snippet.
"""

import torch
import torch.nn as nn

from .embeddings import CodeEmbedding
from .attention import (
    MultiHeadSelfAttention,
    VulnerabilityAttention,
    FeedForwardNetwork,
)


class TransformerEncoderLayer(nn.Module):
    """
    Single transformer encoder layer with pre-norm architecture.
    
    Uses pre-layer-normalization (Pre-LN) instead of the original post-LN
    for more stable training. Each layer consists of:
    1. LayerNorm → Multi-Head Self-Attention → Residual
    2. LayerNorm → Feed-Forward Network → Residual
    """

    def __init__(
        self,
        d_model: int = 512,
        num_heads: int = 8,
        d_ff: int = 2048,
        dropout: float = 0.1,
        activation: str = "gelu",
    ):
        super().__init__()

        self.self_attention = MultiHeadSelfAttention(
            d_model=d_model, num_heads=num_heads, dropout=dropout
        )
        self.feed_forward = FeedForwardNetwork(
            d_model=d_model, d_ff=d_ff, dropout=dropout, activation=activation
        )

        self.norm1 = nn.LayerNorm(d_model, eps=1e-6)
        self.norm2 = nn.LayerNorm(d_model, eps=1e-6)
        self.dropout = nn.Dropout(p=dropout)

    def forward(
        self,
        x: torch.Tensor,
        mask: torch.Tensor | None = None,
        return_attention: bool = False,
    ) -> tuple[torch.Tensor, torch.Tensor | None]:
        """
        Forward pass through encoder layer.
        
        Args:
            x: Input of shape (batch_size, seq_len, d_model).
            mask: Optional attention mask.
            return_attention: Whether to return attention weights.
            
        Returns:
            Tuple of (output, attention_weights).
        """
        # Pre-norm self-attention with residual
        residual = x
        x = self.norm1(x)
        attn_output, attn_weights = self.self_attention(
            x, mask=mask, return_attention=return_attention
        )
        x = residual + self.dropout(attn_output)

        # Pre-norm feed-forward with residual
        residual = x
        x = self.norm2(x)
        ff_output = self.feed_forward(x)
        x = residual + self.dropout(ff_output)

        return x, attn_weights


class CodeTransformer(nn.Module):
    """
    CodeTransformer — Transformer-based model for code vulnerability detection.
    
    This is the main model class that orchestrates the full forward pass from
    tokenized code input to vulnerability predictions. It combines:
    
    1. CodeEmbedding: Token + positional + type embeddings
    2. TransformerEncoder: Stack of N self-attention layers
    3. VulnerabilityAttention: Specialized cross-attention for vuln detection
    4. ClassificationHead: Multi-label vulnerability classifier
    
    The model outputs probability scores for each vulnerability class,
    enabling detection of multiple vulnerabilities in a single code sample.
    
    Parameters (~25M for default configuration):
        - Embedding: vocab_size × d_model ≈ 16.4M
        - Encoder: 6 layers × ~4.2M ≈ 6.3M
        - Vulnerability Attention: ~2.1M
        - Classification Head: ~0.3M
    """

    def __init__(
        self,
        vocab_size: int = 32000,
        d_model: int = 512,
        num_heads: int = 8,
        num_layers: int = 6,
        d_ff: int = 2048,
        max_seq_length: int = 2048,
        num_vuln_classes: int = 11,
        dropout: float = 0.1,
        activation: str = "gelu",
        padding_idx: int = 0,
    ):
        """
        Args:
            vocab_size: Size of the token vocabulary.
            d_model: Model hidden dimension.
            num_heads: Number of attention heads per layer.
            num_layers: Number of transformer encoder layers.
            d_ff: Feed-forward intermediate dimension.
            max_seq_length: Maximum input sequence length.
            num_vuln_classes: Number of vulnerability classes to detect.
            dropout: Dropout probability throughout the model.
            activation: Activation function ('gelu' or 'relu').
            padding_idx: Padding token index in vocabulary.
        """
        super().__init__()

        self.d_model = d_model
        self.num_vuln_classes = num_vuln_classes
        self.max_seq_length = max_seq_length

        # Embedding layer
        self.embedding = CodeEmbedding(
            vocab_size=vocab_size,
            d_model=d_model,
            max_len=max_seq_length,
            dropout=dropout,
            padding_idx=padding_idx,
        )

        # Transformer encoder layers
        self.encoder_layers = nn.ModuleList(
            [
                TransformerEncoderLayer(
                    d_model=d_model,
                    num_heads=num_heads,
                    d_ff=d_ff,
                    dropout=dropout,
                    activation=activation,
                )
                for _ in range(num_layers)
            ]
        )

        # Final encoder normalization
        self.encoder_norm = nn.LayerNorm(d_model, eps=1e-6)

        # Vulnerability-focused attention
        self.vuln_attention = VulnerabilityAttention(
            d_model=d_model,
            num_vuln_classes=num_vuln_classes,
            num_heads=4,
            dropout=dropout,
        )

        # Global pooling (for combining sequence-level and vuln-level features)
        self.global_pool_proj = nn.Linear(d_model, d_model)

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(d_model * 2, d_model),
            nn.GELU(),
            nn.Dropout(p=dropout),
            nn.Linear(d_model, d_model // 2),
            nn.GELU(),
            nn.Dropout(p=dropout),
            nn.Linear(d_model // 2, 1),
        )

        # Confidence calibration layer
        self.confidence_layer = nn.Sequential(
            nn.Linear(d_model, d_model // 4),
            nn.GELU(),
            nn.Linear(d_model // 4, 1),
            nn.Sigmoid(),
        )

        self._init_classifier_weights()

    def _init_classifier_weights(self):
        """Initialize classification head weights."""
        for module in self.classifier:
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                nn.init.zeros_(module.bias)

        for module in self.confidence_layer:
            if isinstance(module, nn.Linear):
                nn.init.xavier_uniform_(module.weight)
                nn.init.zeros_(module.bias)

    def _create_padding_mask(self, input_ids: torch.Tensor) -> torch.Tensor:
        """
        Create padding mask from input IDs.
        
        Args:
            input_ids: Token IDs where 0 = padding.
            
        Returns:
            Mask tensor where 1 = masked (padding), 0 = valid.
            Shape: (batch_size, 1, 1, seq_len)
        """
        mask = (input_ids == 0).unsqueeze(1).unsqueeze(2)
        return mask.float()

    def forward(
        self,
        input_ids: torch.Tensor,
        token_type_ids: torch.Tensor | None = None,
        attention_mask: torch.Tensor | None = None,
        return_attention: bool = False,
    ) -> dict[str, torch.Tensor]:
        """
        Full forward pass through the CodeTransformer.
        
        Args:
            input_ids: Tokenized code, shape (batch_size, seq_len).
            token_type_ids: Optional token types, shape (batch_size, seq_len).
            attention_mask: Optional external mask. If None, auto-generated
                          from padding tokens.
            return_attention: If True, include attention maps in output.
            
        Returns:
            Dictionary containing:
            - 'logits': Raw prediction scores, shape (batch, num_vuln_classes)
            - 'probabilities': Sigmoid probabilities, shape (batch, num_vuln_classes)
            - 'confidence': Calibrated confidence scores, shape (batch, num_vuln_classes)
            - 'encoder_output': Final encoder state, shape (batch, seq_len, d_model)
            - 'attention_weights': (optional) List of attention weight tensors
        """
        # Create padding mask
        if attention_mask is None:
            mask = self._create_padding_mask(input_ids)
        else:
            mask = attention_mask

        # Embed tokens
        x = self.embedding(input_ids, token_type_ids=token_type_ids)

        # Pass through transformer encoder layers
        all_attention_weights = []
        for layer in self.encoder_layers:
            x, attn_weights = layer(x, mask=mask, return_attention=return_attention)
            if return_attention and attn_weights is not None:
                all_attention_weights.append(attn_weights)

        # Final encoder normalization
        encoder_output = self.encoder_norm(x)

        # Vulnerability attention — produces per-class representations
        vuln_repr, vuln_attn = self.vuln_attention(
            encoder_output, mask=mask, return_attention=return_attention
        )
        if return_attention and vuln_attn is not None:
            all_attention_weights.append(vuln_attn)

        # Global average pooling of encoder output (ignoring padding)
        if attention_mask is not None:
            padding_mask = attention_mask.squeeze(1).squeeze(1)  # (batch, seq_len)
        else:
            padding_mask = (input_ids == 0).float()  # 1 where padded

        # Invert: 1 for valid tokens, 0 for padding
        valid_mask = 1.0 - padding_mask
        valid_mask = valid_mask.unsqueeze(-1)  # (batch, seq_len, 1)

        # Masked average pooling
        pooled = (encoder_output * valid_mask).sum(dim=1) / (
            valid_mask.sum(dim=1).clamp(min=1e-9)
        )
        pooled = self.global_pool_proj(pooled)  # (batch, d_model)

        # Expand pooled to match vuln_repr shape for concatenation
        pooled_expanded = pooled.unsqueeze(1).expand_as(vuln_repr)

        # Combine vulnerability-specific and global representations
        combined = torch.cat(
            [vuln_repr, pooled_expanded], dim=-1
        )  # (batch, num_vuln, d_model*2)

        # Classification
        logits = self.classifier(combined).squeeze(-1)  # (batch, num_vuln_classes)
        probabilities = torch.sigmoid(logits)

        # Confidence calibration
        confidence = self.confidence_layer(vuln_repr).squeeze(
            -1
        )  # (batch, num_vuln_classes)

        output = {
            "logits": logits,
            "probabilities": probabilities,
            "confidence": confidence,
            "encoder_output": encoder_output,
        }

        if return_attention:
            output["attention_weights"] = all_attention_weights

        return output

    def count_parameters(self) -> dict[str, int]:
        """
        Count model parameters by component.
        
        Returns:
            Dictionary mapping component names to parameter counts.
        """
        param_counts = {
            "embedding": sum(
                p.numel() for p in self.embedding.parameters() if p.requires_grad
            ),
            "encoder": sum(
                p.numel()
                for layer in self.encoder_layers
                for p in layer.parameters()
                if p.requires_grad
            ),
            "vuln_attention": sum(
                p.numel()
                for p in self.vuln_attention.parameters()
                if p.requires_grad
            ),
            "classifier": sum(
                p.numel() for p in self.classifier.parameters() if p.requires_grad
            )
            + sum(
                p.numel()
                for p in self.confidence_layer.parameters()
                if p.requires_grad
            )
            + sum(
                p.numel()
                for p in self.global_pool_proj.parameters()
                if p.requires_grad
            ),
        }
        param_counts["total"] = sum(param_counts.values())
        return param_counts

    @classmethod
    def from_config(cls, config: dict) -> "CodeTransformer":
        """
        Create a CodeTransformer from a configuration dictionary.
        
        Args:
            config: Model configuration (typically from model_config.yaml).
            
        Returns:
            Initialized CodeTransformer instance.
        """
        model_cfg = config.get("model", config)
        return cls(
            vocab_size=model_cfg.get("vocab_size", 32000),
            d_model=model_cfg.get("embedding_dim", 512),
            num_heads=model_cfg.get("num_heads", 8),
            num_layers=model_cfg.get("num_layers", 6),
            d_ff=model_cfg.get("feedforward_dim", 2048),
            max_seq_length=model_cfg.get("max_seq_length", 2048),
            num_vuln_classes=model_cfg.get("num_vulnerability_classes", 11),
            dropout=model_cfg.get("dropout", 0.1),
            activation=model_cfg.get("activation", "gelu"),
        )
