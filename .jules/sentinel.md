## 2025-02-27 - [Insecure Deserialization in PyTorch checkpoints]
**Vulnerability:** Found `torch.load()` without `weights_only=True` when loading model checkpoints, which uses `pickle` and is vulnerable to arbitrary code execution if a maliciously crafted checkpoint is loaded.
**Learning:** Machine learning models are often shared and downloaded. PyTorch's default `load` behavior relies on `pickle`. Unpickling untrusted data is a classic CWE-502 vulnerability.
**Prevention:** Always use `weights_only=True` with `torch.load` to enforce a safe restricted unpickler, or use `safetensors` format for saving and loading model weights.
