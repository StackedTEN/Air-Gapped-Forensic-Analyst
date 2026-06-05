"""air-gapped-forensic-analyst — a local-LLM DFIR agent grounded in deterministic tools.

The evidence never leaves the host. The model orchestrates an investigation by
calling forensic tools; every fact in an answer is traceable to a tool result.
"""

from .loader import Evidence, load_evidence
from .models import Answer, ToolCall
from .package import load_package, verify_package
from .providers import CloudProvider, LocalOllamaProvider, OfflinePlanner, get_provider
from .tools import dispatch, map_attack, tool_names, tool_specs

__version__ = "0.1.0"

__all__ = [
    "Evidence", "load_evidence", "load_package", "verify_package", "Answer", "ToolCall",
    "OfflinePlanner", "LocalOllamaProvider", "CloudProvider", "get_provider",
    "dispatch", "map_attack", "tool_specs", "tool_names",
]
