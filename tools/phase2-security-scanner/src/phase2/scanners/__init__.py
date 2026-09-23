"""Scanner package. Each scanner exposes ``scan(ctx) -> ScannerRun``."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ..models import FileEntry, Technology
from ..utils.filesystem import DEFAULT_MAX_FILE_SIZE, read_text


@dataclass
class ScanContext:
    root: Path
    files: list[FileEntry]
    use_external_tools: bool = True
    technologies: list[Technology] = field(default_factory=list)
    git_history_depth: int = 100
    tool_timeout: int = 180
    max_file_size: int = DEFAULT_MAX_FILE_SIZE
    rules_dir: Path | None = None
    verbose: bool = False
    _text_cache: dict[str, str | None] = field(default_factory=dict)
    files_by_rel: dict[str, FileEntry] = field(default_factory=dict)
    cache: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.files_by_rel:
            self.files_by_rel = {f.rel: f for f in self.files}

    def text(self, entry: FileEntry) -> str | None:
        if entry.rel not in self._text_cache:
            self._text_cache[entry.rel] = read_text(entry.path, self.max_file_size)
        return self._text_cache[entry.rel]

    def by_name(self, *names: str) -> list[FileEntry]:
        wanted = {n.lower() for n in names}
        return [f for f in self.files if f.name.lower() in wanted]

    def has_tech(self, name: str) -> bool:
        return any(t.name == name for t in self.technologies)


def rules_directory(override: Path | None = None) -> Path:
    if override is not None:
        return override
    here = Path(__file__).resolve().parent.parent
    for candidate in (here / "rules", here.parent.parent / "rules"):
        if (candidate / "secret-patterns.yaml").is_file():
            return candidate
    raise FileNotFoundError("rules directory not found (expected rules/secret-patterns.yaml)")


def load_rules(filename: str, override: Path | None = None) -> list[dict[str, Any]]:
    path = rules_directory(override) / filename
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise ValueError(f"{filename}: expected a mapping with a 'rules' list")
    rules = []
    for raw in data["rules"]:
        if not isinstance(raw, dict) or "id" not in raw or "regex" not in raw:
            raise ValueError(f"{filename}: every rule needs 'id' and 'regex'")
        rule = dict(raw)
        rule["compiled"] = re.compile(rule["regex"])
        rules.append(rule)
    return rules


def load_json_file(ctx: ScanContext, entry: FileEntry) -> Any | None:
    text = ctx.text(entry)
    if text is None:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError):
        return None
