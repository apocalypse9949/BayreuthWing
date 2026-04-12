"""
BAYREUTHWING — Training Module
Training loop, evaluation, and learning rate scheduling.
"""

from .trainer import Trainer
from .evaluator import Evaluator

__all__ = ["Trainer", "Evaluator"]
