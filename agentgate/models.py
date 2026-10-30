"""Untrusted actions cannot supply identity, security labels, or policy."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator

LEVELS = {"PUBLIC": 0, "INTERNAL": 1, "CONFIDENTIAL": 2, "RESTRICTED": 3}


class Label(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    level: Literal["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"] = "PUBLIC"
    compartments: frozenset[str] = frozenset()

    def dominates(self, other: "Label") -> bool:
        return LEVELS[self.level] >= LEVELS[other.level] and self.compartments >= other.compartments

    def join(self, other: "Label") -> "Label":
        level = max((self.level, other.level), key=LEVELS.__getitem__)
        return Label(level=level, compartments=self.compartments | other.compartments)

    def as_dict(self) -> dict:
        return {"level": self.level, "compartments": sorted(self.compartments)}

    def __str__(self):
        return self.level + (" · " + ", ".join(sorted(self.compartments)) if self.compartments else "")


class Action(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)
    operation: Literal["read_document", "save_report", "deliver"]
    resource: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,31}/[a-zA-Z0-9_-]{1,80}$")
    content: str | None = Field(default=None, max_length=50000)
    recipient: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]{0,40}$")

    @model_validator(mode="after")
    def shape(self):
        if self.operation == "save_report":
            if not self.content or not self.content.strip() or self.recipient is not None:
                raise ValueError("save_report requires nonempty content and no recipient")
        elif self.operation == "deliver":
            if self.recipient is None or self.content is not None:
                raise ValueError("deliver requires recipient and forbids inline content")
        elif self.content is not None or self.recipient is not None:
            raise ValueError("read_document accepts only a resource")
        return self


class Principal(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    clearance: Label
    operations: frozenset[str]
    read_scopes: tuple[str, ...]
    write_scopes: tuple[str, ...]
    recipients: frozenset[str]


class Policy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: str
    principals: dict[str, Principal]
    recipients: dict[str, Label]


class Decision(BaseModel):
    allowed: bool
    code: str
    reason: str
    event_id: int
    effective_label: dict | None = None
    data: dict | None = None
