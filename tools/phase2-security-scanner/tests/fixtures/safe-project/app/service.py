import json
import subprocess

import yaml


def load_config(text: str) -> dict:
    return yaml.safe_load(text)


def git_version() -> str:
    return subprocess.run(["git", "--version"], capture_output=True, text=True, check=False).stdout


def get_user(conn, user_id: int):
    return conn.execute("SELECT id, name FROM users WHERE id = ?", (user_id,)).fetchall()


def evaluate(model):
    model.eval()
    return json.dumps({"ok": True})
