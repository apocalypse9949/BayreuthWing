"""
BAYREUTHWING — Learning Rate Scheduler

Custom cosine annealing with warmup schedule for stable transformer training.
"""

import math


class CosineWarmupScheduler:
    """
    Cosine annealing learning rate schedule with linear warmup.
    
    During warmup, LR linearly increases from 0 to base_lr.
    After warmup, LR follows a cosine decay to min_lr.
    
    This schedule is particularly effective for transformers, providing
    gradual warmup to avoid early instability and smooth decay for
    convergence.
    """

    def __init__(
        self,
        optimizer,
        warmup_steps: int = 500,
        total_steps: int = 10000,
        base_lr: float = 3e-4,
        min_lr: float = 1e-6,
    ):
        """
        Args:
            optimizer: PyTorch optimizer.
            warmup_steps: Number of linear warmup steps.
            total_steps: Total training steps.
            base_lr: Peak learning rate after warmup.
            min_lr: Minimum learning rate at end of cosine decay.
        """
        self.optimizer = optimizer
        self.warmup_steps = warmup_steps
        self.total_steps = total_steps
        self.base_lr = base_lr
        self.min_lr = min_lr
        self.current_step = 0

    def step(self):
        """Update learning rate for the current step."""
        self.current_step += 1
        lr = self._compute_lr()

        for param_group in self.optimizer.param_groups:
            param_group["lr"] = lr

    def _compute_lr(self) -> float:
        """Compute learning rate for current step."""
        if self.current_step <= self.warmup_steps:
            # Linear warmup
            return self.base_lr * (self.current_step / max(1, self.warmup_steps))
        else:
            # Cosine decay
            progress = (self.current_step - self.warmup_steps) / max(
                1, self.total_steps - self.warmup_steps
            )
            progress = min(progress, 1.0)
            cosine_decay = 0.5 * (1.0 + math.cos(math.pi * progress))
            return self.min_lr + (self.base_lr - self.min_lr) * cosine_decay

    def get_lr(self) -> float:
        """Get current learning rate."""
        return self._compute_lr()

    def state_dict(self) -> dict:
        """Get scheduler state for checkpointing."""
        return {
            "current_step": self.current_step,
            "warmup_steps": self.warmup_steps,
            "total_steps": self.total_steps,
            "base_lr": self.base_lr,
            "min_lr": self.min_lr,
        }

    def load_state_dict(self, state_dict: dict):
        """Load scheduler state from checkpoint."""
        self.current_step = state_dict["current_step"]
        self.warmup_steps = state_dict["warmup_steps"]
        self.total_steps = state_dict["total_steps"]
        self.base_lr = state_dict["base_lr"]
        self.min_lr = state_dict["min_lr"]
