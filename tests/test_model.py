"""
BAYREUTHWING — Test Suite: Model Tests
"""

import sys
import os
import pytest
import torch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.model.transformer import CodeTransformer
from src.model.tokenizer import CodeTokenizer
from src.model.embeddings import CodeEmbedding, SinusoidalPositionalEncoding
from src.model.attention import MultiHeadSelfAttention, VulnerabilityAttention


class TestCodeTokenizer:
    """Tests for the CodeTokenizer."""

    def setup_method(self):
        self.tokenizer = CodeTokenizer(vocab_size=32000, max_length=256)

    def test_tokenize_python(self):
        code = 'def hello():\n    print("world")'
        tokens = self.tokenizer.tokenize(code)
        assert len(tokens) > 0
        assert any(t["token"] == "def" for t in tokens)
        assert any(t["type_name"] == "keyword" for t in tokens)

    def test_encode_returns_correct_keys(self):
        code = "x = 42"
        result = self.tokenizer.encode(code, max_length=32)
        assert "input_ids" in result
        assert "token_type_ids" in result
        assert "attention_mask" in result

    def test_encode_padding(self):
        code = "x = 1"
        result = self.tokenizer.encode(code, max_length=64)
        assert len(result["input_ids"]) == 64
        assert result["attention_mask"][-1] == 0  # Padding

    def test_encode_truncation(self):
        code = "x = 1\n" * 1000
        result = self.tokenizer.encode(code, max_length=128)
        assert len(result["input_ids"]) == 128

    def test_security_sensitive_detection(self):
        code = 'eval(user_input)\nos.system("cmd")'
        tokens = self.tokenizer.tokenize(code)
        sensitive = [t for t in tokens if t["is_security_sensitive"]]
        assert len(sensitive) > 0

    def test_vocab_info(self):
        info = self.tokenizer.vocab_info()
        assert info["vocab_size"] == 32000
        assert info["num_keywords"] > 0


class TestCodeEmbedding:
    """Tests for the embedding layer."""

    def test_output_shape(self):
        embed = CodeEmbedding(vocab_size=1000, d_model=64, max_len=128)
        input_ids = torch.randint(0, 1000, (2, 32))
        output = embed(input_ids)
        assert output.shape == (2, 32, 64)

    def test_with_token_types(self):
        embed = CodeEmbedding(vocab_size=1000, d_model=64)
        input_ids = torch.randint(0, 1000, (2, 32))
        token_types = torch.randint(0, 10, (2, 32))
        output = embed(input_ids, token_type_ids=token_types)
        assert output.shape == (2, 32, 64)


class TestMultiHeadAttention:
    """Tests for multi-head attention."""

    def test_output_shape(self):
        attn = MultiHeadSelfAttention(d_model=64, num_heads=4)
        x = torch.randn(2, 16, 64)
        output, _ = attn(x)
        assert output.shape == (2, 16, 64)

    def test_attention_weights(self):
        attn = MultiHeadSelfAttention(d_model=64, num_heads=4)
        x = torch.randn(2, 16, 64)
        output, weights = attn(x, return_attention=True)
        assert weights is not None
        assert weights.shape == (2, 4, 16, 16)


class TestVulnerabilityAttention:
    """Tests for vulnerability attention."""

    def test_output_shape(self):
        vuln_attn = VulnerabilityAttention(d_model=64, num_vuln_classes=11, num_heads=4)
        code_repr = torch.randn(2, 32, 64)
        vuln_repr, _ = vuln_attn(code_repr)
        assert vuln_repr.shape == (2, 11, 64)

    def test_with_attention_weights(self):
        vuln_attn = VulnerabilityAttention(d_model=64, num_vuln_classes=11, num_heads=4)
        code_repr = torch.randn(2, 32, 64)
        vuln_repr, weights = vuln_attn(code_repr, return_attention=True)
        assert weights is not None
        assert weights.shape[2] == 11  # num_vuln_classes


class TestCodeTransformer:
    """Tests for the full model."""

    def setup_method(self):
        self.model = CodeTransformer(
            vocab_size=1000,
            d_model=64,
            num_heads=4,
            num_layers=2,
            d_ff=128,
            max_seq_length=64,
            num_vuln_classes=11,
            dropout=0.0,
        )

    def test_forward_shape(self):
        input_ids = torch.randint(1, 1000, (2, 32))
        output = self.model(input_ids)
        assert output["logits"].shape == (2, 11)
        assert output["probabilities"].shape == (2, 11)
        assert output["confidence"].shape == (2, 11)

    def test_probabilities_range(self):
        input_ids = torch.randint(1, 1000, (2, 32))
        output = self.model(input_ids)
        probs = output["probabilities"]
        assert (probs >= 0).all() and (probs <= 1).all()

    def test_parameter_count(self):
        params = self.model.count_parameters()
        assert params["total"] > 0
        assert "embedding" in params
        assert "encoder" in params

    def test_from_config(self):
        config = {
            "model": {
                "vocab_size": 500,
                "embedding_dim": 32,
                "num_heads": 2,
                "num_layers": 1,
                "feedforward_dim": 64,
                "max_seq_length": 32,
                "num_vulnerability_classes": 5,
            }
        }
        model = CodeTransformer.from_config(config)
        input_ids = torch.randint(1, 500, (1, 16))
        output = model(input_ids)
        assert output["logits"].shape == (1, 5)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
