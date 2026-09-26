"""Small, explicit module contract for SORS observations.

Only modules named in modules.json are imported. Installed Python modules are
executable code; enable third-party modules only when you trust their author.
"""

from datetime import datetime, timezone
import importlib
import json
from pathlib import Path
import re

SCHEMA = "sors.observation.v1"
IDENTIFIER = re.compile(r"^[a-z][a-z0-9_]{1,39}$")


def observation(module_id, subject, status, facts, coverage=None):
    if not IDENTIFIER.fullmatch(module_id) or status not in {"complete", "partial", "unsupported"}:
        raise ValueError("Invalid module observation")
    if not isinstance(subject, str) or not subject or not isinstance(facts, dict):
        raise ValueError("Invalid observation subject or facts")
    return {"schema": SCHEMA, "module": module_id,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "subject": subject, "status": status, "coverage": coverage or {},
            "facts": facts}


class Registry:
    def __init__(self):
        self._modules = {}

    def register(self, module):
        manifest = module.manifest
        module_id = manifest.get("id")
        if not isinstance(module_id, str) or not IDENTIFIER.fullmatch(module_id):
            raise ValueError("Invalid module id")
        if module_id in self._modules or manifest.get("input_kind") not in {"form", "local", "text_file"}:
            raise ValueError("Duplicate module or unsupported input kind")
        if not callable(getattr(module, "run", None)):
            raise ValueError("Module needs run(payload)")
        self._modules[module_id] = module

    def manifests(self):
        return [dict(module.manifest) for module in self._modules.values()]

    def run(self, module_id, payload):
        module = self._modules.get(module_id)
        if module is None:
            raise KeyError(module_id)
        result = module.run(payload)
        if not isinstance(result, dict) or result.get("schema") != SCHEMA or result.get("module") != module_id:
            raise ValueError("Module returned an invalid observation")
        return result


def load_registry(config=Path(__file__).with_name("modules.json")):
    registry = Registry()
    entries = json.loads(config.read_text(encoding="utf-8"))
    if not isinstance(entries, list):
        raise ValueError("Module config must be a list")
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("python_module"), str):
            raise ValueError("Invalid module config entry")
        if entry.get("enabled", True):
            registry.register(importlib.import_module(entry["python_module"]).create_module())
    return registry
