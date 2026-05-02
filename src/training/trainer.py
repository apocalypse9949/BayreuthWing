"""
BAYREUTHWING — Model Trainer

Complete training pipeline with:
- Mixed-precision training (AMP)
- Gradient clipping
- Cosine warmup LR scheduling
- Early stopping with best-model checkpointing
- Rich progress display
- Training history logging
"""

import os
import time
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from torch.cuda.amp import autocast, GradScaler
from typing import Optional

from ..model.transformer import CodeTransformer
from ..data.dataset import VulnCodeDataset
from .scheduler import CosineWarmupScheduler
from .evaluator import Evaluator


class Trainer:
    """
    Training engine for the CodeTransformer model.
    
    Handles the complete training lifecycle: data loading, forward/backward
    passes, optimization, validation, checkpointing, and early stopping.
    """

    def __init__(
        self,
        model: CodeTransformer,
        train_dataset: VulnCodeDataset,
        val_dataset: Optional[VulnCodeDataset] = None,
        config: Optional[dict] = None,
    ):
        """
        Args:
            model: CodeTransformer model instance.
            train_dataset: Training dataset.
            val_dataset: Validation dataset (for early stopping).
            config: Training configuration dict.
        """
        self.config = config or {}
        train_cfg = self.config.get("training", self.config)

        # Device selection
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model = model.to(self.device)

        # Training parameters
        self.epochs = train_cfg.get("epochs", 50)
        self.batch_size = train_cfg.get("batch_size", 32)
        self.learning_rate = train_cfg.get("learning_rate", 3e-4)
        self.weight_decay = train_cfg.get("weight_decay", 0.01)
        self.max_grad_norm = train_cfg.get("max_grad_norm", 1.0)
        self.mixed_precision = train_cfg.get("mixed_precision", True) and torch.cuda.is_available()
        self.patience = train_cfg.get("early_stopping_patience", 5)
        self.checkpoint_dir = train_cfg.get("checkpoint_dir", "checkpoints")
        self.log_interval = train_cfg.get("log_interval", 10)

        # Data loaders
        self.train_loader = DataLoader(
            train_dataset,
            batch_size=self.batch_size,
            shuffle=True,
            collate_fn=VulnCodeDataset.collate_fn,
            num_workers=0,
            pin_memory=torch.cuda.is_available(),
        )

        self.val_loader = None
        if val_dataset:
            self.val_loader = DataLoader(
                val_dataset,
                batch_size=self.batch_size,
                shuffle=False,
                collate_fn=VulnCodeDataset.collate_fn,
                num_workers=0,
                pin_memory=torch.cuda.is_available(),
            )

        # Loss function with class weights
        class_weights = train_dataset.get_class_weights().to(self.device)
        self.criterion = nn.BCEWithLogitsLoss(pos_weight=class_weights)

        # Optimizer (AdamW with weight decay)
        self.optimizer = torch.optim.AdamW(
            self.model.parameters(),
            lr=self.learning_rate,
            weight_decay=self.weight_decay,
            betas=(0.9, 0.999),
            eps=1e-8,
        )

        # LR scheduler
        total_steps = len(self.train_loader) * self.epochs
        warmup_steps = train_cfg.get("warmup_steps", min(500, total_steps // 10))
        self.scheduler = CosineWarmupScheduler(
            optimizer=self.optimizer,
            warmup_steps=warmup_steps,
            total_steps=total_steps,
            base_lr=self.learning_rate,
        )

        # Mixed precision scaler
        self.scaler = GradScaler() if self.mixed_precision else None

        # Evaluator
        vuln_names = [
            "SQL Injection", "XSS", "Command Injection", "Path Traversal",
            "Hardcoded Credentials", "Insecure Deserialization",
            "Weak Cryptography", "Buffer Overflow", "SSRF",
            "Data Exposure", "Insecure Random",
        ]
        self.evaluator = Evaluator(
            num_classes=model.num_vuln_classes,
            class_names=vuln_names,
        )

        # Training state
        self.best_val_loss = float("inf")
        self.patience_counter = 0
        self.history = {
            "train_loss": [],
            "val_loss": [],
            "val_f1": [],
            "learning_rate": [],
        }

        # Create checkpoint directory
        os.makedirs(self.checkpoint_dir, exist_ok=True)

    def train(self, verbose: bool = True) -> dict:
        """
        Run the complete training loop.
        
        Args:
            verbose: If True, print progress to console.
            
        Returns:
            Training history dictionary.
        """
        if verbose:
            print("=" * 70)
            print("  BAYREUTHWING — TRAINING STARTED")
            print("=" * 70)
            params = self.model.count_parameters()
            print(f"  Model Parameters: {params['total']:,}")
            print(f"  Device: {self.device}")
            print(f"  Epochs: {self.epochs}")
            print(f"  Batch Size: {self.batch_size}")
            print(f"  Learning Rate: {self.learning_rate}")
            print(f"  Mixed Precision: {self.mixed_precision}")
            print(f"  Training Samples: {len(self.train_loader.dataset)}")
            if self.val_loader:
                print(f"  Validation Samples: {len(self.val_loader.dataset)}")
            print("=" * 70)

        for epoch in range(1, self.epochs + 1):
            # ── Train epoch ─────────────────────────────────────
            train_loss = self._train_epoch(epoch, verbose)
            self.history["train_loss"].append(train_loss)
            self.history["learning_rate"].append(self.scheduler.get_lr())

            # ── Validate ────────────────────────────────────────
            if self.val_loader:
                val_loss, val_metrics = self._validate(epoch, verbose)
                self.history["val_loss"].append(val_loss)
                self.history["val_f1"].append(val_metrics.get("macro", {}).get("f1", 0.0))

                # ── Early stopping check ────────────────────────
                if val_loss < self.best_val_loss:
                    self.best_val_loss = val_loss
                    self.patience_counter = 0
                    self._save_checkpoint(epoch, is_best=True)
                    if verbose:
                        print(f"  ✓ New best model saved (val_loss: {val_loss:.4f})")
                else:
                    self.patience_counter += 1
                    if verbose:
                        print(
                            f"  ✗ No improvement ({self.patience_counter}/{self.patience})"
                        )

                    if self.patience_counter >= self.patience:
                        if verbose:
                            print(f"\n  Early stopping at epoch {epoch}")
                        break
            else:
                # Save periodically without validation
                if epoch % 5 == 0:
                    self._save_checkpoint(epoch, is_best=False)

            if verbose:
                print()

        # Save final model
        self._save_checkpoint(epoch, is_best=False, filename="model_final.pt")

        if verbose:
            print("=" * 70)
            print("  TRAINING COMPLETE")
            print(f"  Best Validation Loss: {self.best_val_loss:.4f}")
            print("=" * 70)

        return self.history

    def _train_epoch(self, epoch: int, verbose: bool) -> float:
        """Run a single training epoch."""
        self.model.train()
        epoch_loss = 0.0
        num_batches = 0
        start_time = time.time()

        for batch_idx, batch in enumerate(self.train_loader):
            # Move to device
            input_ids = batch["input_ids"].to(self.device)
            token_type_ids = batch["token_type_ids"].to(self.device)
            labels = batch["labels"].to(self.device)

            # Forward pass
            self.optimizer.zero_grad()

            if self.mixed_precision:
                with autocast():
                    outputs = self.model(input_ids, token_type_ids=token_type_ids)
                    loss = self.criterion(outputs["logits"], labels)

                self.scaler.scale(loss).backward()

                # Gradient clipping
                self.scaler.unscale_(self.optimizer)
                torch.nn.utils.clip_grad_norm_(
                    self.model.parameters(), self.max_grad_norm
                )

                self.scaler.step(self.optimizer)
                self.scaler.update()
            else:
                outputs = self.model(input_ids, token_type_ids=token_type_ids)
                loss = self.criterion(outputs["logits"], labels)

                loss.backward()

                # Gradient clipping
                torch.nn.utils.clip_grad_norm_(
                    self.model.parameters(), self.max_grad_norm
                )

                self.optimizer.step()

            # Update LR
            self.scheduler.step()

            epoch_loss += loss.item()
            num_batches += 1

            # Log progress
            if verbose and (batch_idx + 1) % self.log_interval == 0:
                avg_loss = epoch_loss / num_batches
                lr = self.scheduler.get_lr()
                elapsed = time.time() - start_time
                print(
                    f"  Epoch {epoch:3d} | "
                    f"Batch {batch_idx + 1:4d}/{len(self.train_loader)} | "
                    f"Loss: {avg_loss:.4f} | "
                    f"LR: {lr:.2e} | "
                    f"Time: {elapsed:.1f}s"
                )

        avg_epoch_loss = epoch_loss / max(1, num_batches)

        if verbose:
            elapsed = time.time() - start_time
            print(
                f"  Epoch {epoch:3d} | "
                f"Train Loss: {avg_epoch_loss:.4f} | "
                f"Time: {elapsed:.1f}s"
            )

        return avg_epoch_loss

    @torch.no_grad()
    def _validate(self, epoch: int, verbose: bool) -> tuple[float, dict]:
        """Run validation and compute metrics."""
        self.model.eval()
        self.evaluator.reset()
        val_loss = 0.0
        num_batches = 0

        for batch in self.val_loader:
            input_ids = batch["input_ids"].to(self.device)
            token_type_ids = batch["token_type_ids"].to(self.device)
            labels = batch["labels"].to(self.device)

            outputs = self.model(input_ids, token_type_ids=token_type_ids)
            loss = self.criterion(outputs["logits"], labels)

            val_loss += loss.item()
            num_batches += 1

            self.evaluator.update(outputs["probabilities"], labels)

        avg_val_loss = val_loss / max(1, num_batches)
        metrics = self.evaluator.compute_metrics()

        if verbose:
            macro_f1 = metrics.get("macro", {}).get("f1", 0.0)
            print(
                f"  Epoch {epoch:3d} | "
                f"Val Loss: {avg_val_loss:.4f} | "
                f"Macro F1: {macro_f1:.4f}"
            )

        return avg_val_loss, metrics

    def _save_checkpoint(
        self,
        epoch: int,
        is_best: bool = False,
        filename: Optional[str] = None,
    ):
        """Save model checkpoint."""
        if filename is None:
            filename = "model_best.pt" if is_best else f"model_epoch_{epoch}.pt"

        checkpoint = {
            "epoch": epoch,
            "model_state_dict": self.model.state_dict(),
            "optimizer_state_dict": self.optimizer.state_dict(),
            "scheduler_state_dict": self.scheduler.state_dict(),
            "best_val_loss": self.best_val_loss,
            "history": self.history,
            "config": self.config,
        }

        path = os.path.join(self.checkpoint_dir, filename)
        torch.save(checkpoint, path)

    def load_checkpoint(self, path: str):
        """Load model from checkpoint."""
        # [SECURITY] Use weights_only=True to prevent arbitrary code execution during deserialization
        checkpoint = torch.load(path, map_location=self.device, weights_only=True)
        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.optimizer.load_state_dict(checkpoint["optimizer_state_dict"])
        self.scheduler.load_state_dict(checkpoint["scheduler_state_dict"])
        self.best_val_loss = checkpoint.get("best_val_loss", float("inf"))
        self.history = checkpoint.get("history", self.history)

        return checkpoint.get("epoch", 0)
