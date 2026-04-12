"""
BAYREUTHWING — VulnCodeDataset

PyTorch Dataset class for loading and serving code vulnerability samples
for model training and evaluation.
"""

import torch
from torch.utils.data import Dataset
from typing import Optional

from ..model.tokenizer import CodeTokenizer


class VulnCodeDataset(Dataset):
    """
    PyTorch Dataset for code vulnerability detection.
    
    Wraps generated/loaded code samples and tokenizes them on-the-fly
    for the CodeTransformer model.
    """

    def __init__(
        self,
        samples: list[dict],
        tokenizer: Optional[CodeTokenizer] = None,
        max_length: int = 512,
        num_classes: int = 11,
    ):
        """
        Args:
            samples: List of sample dicts from SyntheticDataGenerator.
            tokenizer: CodeTokenizer instance. Creates one if not provided.
            max_length: Maximum token sequence length.
            num_classes: Number of vulnerability classes.
        """
        self.samples = samples
        self.tokenizer = tokenizer or CodeTokenizer(max_length=max_length)
        self.max_length = max_length
        self.num_classes = num_classes

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> dict[str, torch.Tensor]:
        """
        Get a single training sample.
        
        Returns dict with:
        - input_ids: (max_length,) long tensor
        - token_type_ids: (max_length,) long tensor
        - attention_mask: (max_length,) float tensor (1=valid, 0=padding)
        - labels: (num_classes,) float tensor (multi-hot)
        """
        sample = self.samples[idx]

        # Tokenize
        encoded = self.tokenizer.encode(
            sample["code"],
            max_length=self.max_length,
            add_special_tokens=True,
            padding=True,
        )

        # Create multi-hot label vector
        labels = torch.zeros(self.num_classes, dtype=torch.float)
        for label_id in sample.get("labels", []):
            if 0 <= label_id < self.num_classes:
                labels[label_id] = 1.0

        return {
            "input_ids": torch.tensor(encoded["input_ids"], dtype=torch.long),
            "token_type_ids": torch.tensor(encoded["token_type_ids"], dtype=torch.long),
            "attention_mask": torch.tensor(encoded["attention_mask"], dtype=torch.float),
            "labels": labels,
        }

    def get_class_weights(self) -> torch.Tensor:
        """
        Compute class weights for handling imbalanced data.
        
        Uses inverse frequency weighting:
        weight = total_samples / (num_classes * class_count)
        
        Returns:
            Tensor of shape (num_classes,) with per-class weights.
        """
        class_counts = torch.zeros(self.num_classes)

        for sample in self.samples:
            for label_id in sample.get("labels", []):
                if 0 <= label_id < self.num_classes:
                    class_counts[label_id] += 1

        # Avoid division by zero
        class_counts = class_counts.clamp(min=1)

        total = len(self.samples)
        weights = total / (self.num_classes * class_counts)

        return weights

    @staticmethod
    def collate_fn(batch: list[dict]) -> dict[str, torch.Tensor]:
        """
        Custom collate function for DataLoader.
        
        Stacks individual samples into batched tensors.
        
        Args:
            batch: List of sample dicts from __getitem__.
            
        Returns:
            Batched dict with stacked tensors.
        """
        return {
            "input_ids": torch.stack([b["input_ids"] for b in batch]),
            "token_type_ids": torch.stack([b["token_type_ids"] for b in batch]),
            "attention_mask": torch.stack([b["attention_mask"] for b in batch]),
            "labels": torch.stack([b["labels"] for b in batch]),
        }

    def split(
        self,
        train_ratio: float = 0.8,
        val_ratio: float = 0.1,
        test_ratio: float = 0.1,
        seed: int = 42,
    ) -> tuple["VulnCodeDataset", "VulnCodeDataset", "VulnCodeDataset"]:
        """
        Split dataset into train/val/test subsets.
        
        Args:
            train_ratio: Fraction for training.
            val_ratio: Fraction for validation.
            test_ratio: Fraction for testing.
            seed: Random seed for reproducibility.
            
        Returns:
            Tuple of (train_dataset, val_dataset, test_dataset).
        """
        assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6

        # Deterministic shuffle
        generator = torch.Generator().manual_seed(seed)
        indices = torch.randperm(len(self.samples), generator=generator).tolist()

        n_train = int(len(indices) * train_ratio)
        n_val = int(len(indices) * val_ratio)

        train_indices = indices[:n_train]
        val_indices = indices[n_train : n_train + n_val]
        test_indices = indices[n_train + n_val :]

        train_samples = [self.samples[i] for i in train_indices]
        val_samples = [self.samples[i] for i in val_indices]
        test_samples = [self.samples[i] for i in test_indices]

        return (
            VulnCodeDataset(train_samples, self.tokenizer, self.max_length, self.num_classes),
            VulnCodeDataset(val_samples, self.tokenizer, self.max_length, self.num_classes),
            VulnCodeDataset(test_samples, self.tokenizer, self.max_length, self.num_classes),
        )
