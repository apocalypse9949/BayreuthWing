## 2024-05-15 - PyTorch Insecure Deserialization
**Vulnerability:** Found `torch.load` being used without `weights_only=True` to load model checkpoints in `src/scanner/engine.py` and `src/training/trainer.py`.
**Learning:** PyTorch's `torch.load` defaults to using Python's `pickle` module, which is vulnerable to arbitrary code execution if a malicious checkpoint file is loaded.
**Prevention:** Always use `weights_only=True` when loading PyTorch checkpoints unless full pickle functionality is explicitly required and the source is fully trusted.
