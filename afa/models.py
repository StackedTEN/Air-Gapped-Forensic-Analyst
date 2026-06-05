"""Result models shared across providers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolCall:
    name: str
    args: dict[str, Any]
    result: dict[str, Any]

    @property
    def summary(self) -> str:
        if "error" in self.result:
            return self.result["error"]
        if "count" in self.result:
            n = self.result["count"]
            extra = ""
            if "suspicious_count" in self.result:
                extra = f", {self.result['suspicious_count']} suspicious"
            return f"{n} result(s){extra}"
        return ", ".join(f"{k}={v}" for k, v in self.result.items() if not isinstance(v, (list, dict)))


@dataclass
class Answer:
    question: str
    text: str
    provider: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    egress_used: bool = False

    @property
    def grounded(self) -> bool:
        """An answer is grounded only if it was built from at least one tool result."""
        return len(self.tool_calls) > 0
