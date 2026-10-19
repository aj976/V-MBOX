"""The sole serializer for canonical persisted or hashed JSON."""

import json
from dataclasses import asdict, is_dataclass
from typing import Any


def canonical_json(value: Any) -> bytes:
    """Serialize as deterministic UTF-8 JSON, without insignificant whitespace.

    Nanosecond timestamps must be supplied as integer fields by validated models.
    Non-finite floats are rejected; finite floats support measured evaluation metrics.
    """
    if callable(getattr(value, "to_dict", None)):
        value = value.to_dict()
    elif is_dataclass(value) and not isinstance(value, type):
        value = asdict(value)
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
