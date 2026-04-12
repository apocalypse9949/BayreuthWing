"""
BAYREUTHWING — Model Evaluator

Computes evaluation metrics for vulnerability detection:
- Per-class precision, recall, F1-score
- Macro/micro averaged metrics
- Confusion matrix
- ROC-AUC per class
"""

import torch
import numpy as np
from typing import Optional


class Evaluator:
    """
    Evaluation engine for the CodeTransformer model.
    
    Accumulates predictions and labels across batches, then
    computes comprehensive metrics for model performance analysis.
    """

    def __init__(
        self,
        num_classes: int = 11,
        threshold: float = 0.5,
        class_names: Optional[list[str]] = None,
    ):
        """
        Args:
            num_classes: Number of vulnerability classes.
            threshold: Probability threshold for positive prediction.
            class_names: Human-readable names for each class.
        """
        self.num_classes = num_classes
        self.threshold = threshold
        self.class_names = class_names or [f"Class_{i}" for i in range(num_classes)]

        self.reset()

    def reset(self):
        """Reset accumulated predictions and labels."""
        self.all_predictions = []
        self.all_labels = []
        self.all_probabilities = []

    def update(
        self,
        probabilities: torch.Tensor,
        labels: torch.Tensor,
    ):
        """
        Accumulate a batch of predictions and labels.
        
        Args:
            probabilities: Model output probabilities, shape (batch, num_classes).
            labels: Ground truth labels, shape (batch, num_classes).
        """
        probs = probabilities.detach().cpu()
        labs = labels.detach().cpu()

        predictions = (probs >= self.threshold).float()

        self.all_probabilities.append(probs)
        self.all_predictions.append(predictions)
        self.all_labels.append(labs)

    def compute_metrics(self) -> dict:
        """
        Compute comprehensive evaluation metrics.
        
        Returns:
            Dictionary with per-class and aggregated metrics.
        """
        if not self.all_predictions:
            return {}

        predictions = torch.cat(self.all_predictions, dim=0).numpy()
        labels = torch.cat(self.all_labels, dim=0).numpy()
        probabilities = torch.cat(self.all_probabilities, dim=0).numpy()

        metrics = {
            "per_class": {},
            "macro": {},
            "micro": {},
            "samples": len(predictions),
        }

        # Per-class metrics
        all_precision = []
        all_recall = []
        all_f1 = []

        total_tp = 0
        total_fp = 0
        total_fn = 0

        for i in range(self.num_classes):
            tp = np.sum((predictions[:, i] == 1) & (labels[:, i] == 1))
            fp = np.sum((predictions[:, i] == 1) & (labels[:, i] == 0))
            fn = np.sum((predictions[:, i] == 0) & (labels[:, i] == 1))
            tn = np.sum((predictions[:, i] == 0) & (labels[:, i] == 0))

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (
                2 * precision * recall / (precision + recall)
                if (precision + recall) > 0
                else 0.0
            )

            # AUC approximation (trapezoidal)
            auc = self._compute_auc(probabilities[:, i], labels[:, i])

            metrics["per_class"][self.class_names[i]] = {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1": round(f1, 4),
                "auc": round(auc, 4),
                "support": int(np.sum(labels[:, i])),
                "tp": int(tp),
                "fp": int(fp),
                "fn": int(fn),
                "tn": int(tn),
            }

            all_precision.append(precision)
            all_recall.append(recall)
            all_f1.append(f1)

            total_tp += tp
            total_fp += fp
            total_fn += fn

        # Macro averages (unweighted mean across classes)
        metrics["macro"]["precision"] = round(np.mean(all_precision), 4)
        metrics["macro"]["recall"] = round(np.mean(all_recall), 4)
        metrics["macro"]["f1"] = round(np.mean(all_f1), 4)

        # Micro averages (computed from total TP/FP/FN)
        micro_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        micro_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        micro_f1 = (
            2 * micro_precision * micro_recall / (micro_precision + micro_recall)
            if (micro_precision + micro_recall) > 0
            else 0.0
        )

        metrics["micro"]["precision"] = round(micro_precision, 4)
        metrics["micro"]["recall"] = round(micro_recall, 4)
        metrics["micro"]["f1"] = round(micro_f1, 4)

        return metrics

    def _compute_auc(self, scores: np.ndarray, labels: np.ndarray) -> float:
        """
        Compute AUC-ROC using the trapezoidal rule.
        
        Args:
            scores: Predicted probabilities.
            labels: Binary ground truth labels.
            
        Returns:
            AUC score.
        """
        # Handle edge cases
        if np.sum(labels) == 0 or np.sum(labels) == len(labels):
            return 0.5

        # Sort by scores descending
        sorted_indices = np.argsort(-scores)
        sorted_labels = labels[sorted_indices]

        # Compute TPR and FPR at each threshold
        total_positives = np.sum(labels)
        total_negatives = len(labels) - total_positives

        tp = 0
        fp = 0
        tpr_list = [0.0]
        fpr_list = [0.0]

        for label in sorted_labels:
            if label == 1:
                tp += 1
            else:
                fp += 1
            tpr_list.append(tp / total_positives)
            fpr_list.append(fp / total_negatives)

        # Trapezoidal AUC
        auc = 0.0
        for i in range(1, len(fpr_list)):
            auc += (fpr_list[i] - fpr_list[i - 1]) * (tpr_list[i] + tpr_list[i - 1]) / 2

        return auc

    def format_report(self, metrics: Optional[dict] = None) -> str:
        """
        Format metrics as a human-readable report string.
        
        Args:
            metrics: Pre-computed metrics dict. If None, computes fresh.
            
        Returns:
            Formatted report string.
        """
        if metrics is None:
            metrics = self.compute_metrics()

        if not metrics:
            return "No evaluation data available."

        lines = []
        lines.append("=" * 80)
        lines.append("  VULNERABILITY DETECTION EVALUATION REPORT")
        lines.append("=" * 80)
        lines.append(f"  Total Samples: {metrics['samples']}")
        lines.append("")

        # Per-class table
        header = f"  {'Class':<35} {'Prec':>7} {'Rec':>7} {'F1':>7} {'AUC':>7} {'Support':>8}"
        lines.append(header)
        lines.append("  " + "-" * 73)

        for class_name, class_metrics in metrics["per_class"].items():
            line = (
                f"  {class_name:<35} "
                f"{class_metrics['precision']:>7.4f} "
                f"{class_metrics['recall']:>7.4f} "
                f"{class_metrics['f1']:>7.4f} "
                f"{class_metrics['auc']:>7.4f} "
                f"{class_metrics['support']:>8d}"
            )
            lines.append(line)

        lines.append("  " + "-" * 73)

        # Macro/Micro averages
        lines.append(
            f"  {'Macro Average':<35} "
            f"{metrics['macro']['precision']:>7.4f} "
            f"{metrics['macro']['recall']:>7.4f} "
            f"{metrics['macro']['f1']:>7.4f}"
        )
        lines.append(
            f"  {'Micro Average':<35} "
            f"{metrics['micro']['precision']:>7.4f} "
            f"{metrics['micro']['recall']:>7.4f} "
            f"{metrics['micro']['f1']:>7.4f}"
        )

        lines.append("=" * 80)
        return "\n".join(lines)
