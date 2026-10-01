"""Immutable metadata, application policies, and admission outcomes."""

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from .quota import QuotaResult

Mode = Literal["observe", "enforce"]
FailureMode = Literal["open", "closed"]


@dataclass(frozen=True)
class RequestMetadata:
    method: str
    route: str
    client_ip: str | None
    headers: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))


@dataclass(frozen=True)
class RuleResult:
    allowed: bool
    reason: str = ""
    status: int = 403


@dataclass(frozen=True)
class Rule:
    id: str
    evaluate: Callable[[Any], RuleResult] = field(repr=False)
    mode: Mode = "observe"
    failure_mode: FailureMode = "closed"


@dataclass(frozen=True)
class Check:
    id: str
    source: str
    mode: Mode
    decision: str
    reason: str
    duration_ms: float = 0.0


@dataclass(frozen=True, eq=False)
class Decision:
    """Reporting accepts only the exact decision issued by the same client."""

    id: str
    timestamp: str
    allowed: bool
    reason: str
    status: int
    degraded: bool
    checks: tuple[Check, ...]
    quota: "QuotaResult | None" = None
    retry_after_seconds: int = 0


@dataclass(frozen=True)
class Outcome:
    handler_attempted: bool = False
    status: int | None = None
    cancelled: bool = False
    handler_error: bool = False
