"""Common health model shared by all probes."""
import enum
from dataclasses import dataclass, field, asdict


class State(enum.Enum):
    RUN = "RUN"
    STOP = "STOP"
    STARTUP = "STARTUP"
    HOLD = "HOLD"
    DEFECT = "DEFECT"
    FAULT = "FAULT"
    UNKNOWN = "UNKNOWN"
    UNREACHABLE = "UNREACHABLE"


@dataclass
class Fault:
    code: str
    description: str
    source: str            # which decode table produced it
    timestamp: str = ""
    raw: str = ""          # hex of the relevant bytes


@dataclass
class PLCHealth:
    host: str
    port: int
    proto: str
    reachable: bool
    state: State
    faults: list = field(default_factory=list)
    identity: dict = field(default_factory=dict)
    raw: str = ""          # hex of the raw response, for forensics

    def healthy(self) -> bool:
        return self.reachable and self.state is State.RUN and not self.faults

    def to_dict(self) -> dict:
        d = asdict(self)
        d["state"] = self.state.value
        return d

    @classmethod
    def unreachable(cls, host, port, proto):
        return cls(host=host, port=port, proto=proto, reachable=False,
                   state=State.UNREACHABLE)
