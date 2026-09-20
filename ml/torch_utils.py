"""
Janus PyTorch Utility — Windows DLL Discovery & Safe Module Importer
===================================================================
Handles Windows PyTorch runtime DLL directory resolution and provides
clean, guarded access to torch, nn, and F across varied environments.
"""

from __future__ import annotations

import importlib.util
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional, Tuple

log = logging.getLogger(__name__)

_TORCH_INITIALIZED = False
_TORCH: Any = None
_NN: Any = None
_F: Any = None


def init_torch_env() -> bool:
    """
    Ensure PyTorch Windows DLL paths are added to the search path before import.
    Returns True if torch is available and initialized, False otherwise.
    """
    global _TORCH_INITIALIZED, _TORCH, _NN, _F

    if _TORCH_INITIALIZED:
        return _TORCH is not None

    # On Windows with Python 3.8+, C++ runtime DLLs in torch/lib must be explicitly added
    if sys.platform == "win32" and hasattr(os, "add_dll_directory"):
        spec = importlib.util.find_spec("torch")
        if spec and spec.origin:
            torch_lib = Path(spec.origin).parent / "lib"
            if torch_lib.is_dir():
                try:
                    os.add_dll_directory(str(torch_lib))
                    log.debug("Added PyTorch DLL directory: %s", torch_lib)
                except Exception as exc:
                    log.debug("Notice: os.add_dll_directory failed for %s: %s", torch_lib, exc)

    try:
        import torch
        import torch.nn as nn
        import torch.nn.functional as F

        _TORCH = torch
        _NN = nn
        _F = F
        _TORCH_INITIALIZED = True
        return True
    except ImportError as exc:
        log.warning("PyTorch is not installed or failed to import: %s", exc)
        _TORCH_INITIALIZED = True
        _TORCH = None
        _NN = None
        _F = None
        return False
    except Exception as exc:
        log.warning("Unexpected error initializing PyTorch: %s", exc)
        _TORCH_INITIALIZED = True
        _TORCH = None
        _NN = None
        _F = None
        return False


def get_torch_modules() -> Tuple[Any, Any, Any]:
    """
    Return (torch, nn, F) tuple.
    Raises RuntimeError if PyTorch cannot be imported.
    """
    if not init_torch_env() or _TORCH is None:
        raise RuntimeError("PyTorch runtime is not available in the current environment.")
    return _TORCH, _NN, _F


def is_torch_available() -> bool:
    """Check if PyTorch can be loaded successfully."""
    return init_torch_env()
