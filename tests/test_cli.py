"""
CLI-level tests for redactctl/cli.py, run as real subprocesses -- the
restore-hook is invoked by Claude Code as a subprocess, so a black-box
test through the actual command line is the only way to catch bugs in
how that subprocess resolves paths, not just what the Python functions
do when called directly in-process.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = REPO_ROOT / "redactctl.py"


def _run_launcher(cwd: Path, args: list, stdin_text: str = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(LAUNCHER)] + args,
        cwd=str(cwd), input=stdin_text, capture_output=True, text=True, timeout=30,
    )


def _new_project(tmp_path, name="proj") -> Path:
    project = tmp_path / name
    project.mkdir()
    shutil.copy(REPO_ROOT / "redactctl.py", project / "redactctl.py")
    shutil.copytree(REPO_ROOT / "redactctl", project / "redactctl")
    return project


# ---------------------------------------------------------------------
# INCIDENT: restore-hook resolved .redaction_map.json as a bare
# relative path against whatever cwd the hook subprocess happened to
# inherit. Claude Code's hook event JSON includes an explicit "cwd"
# field for exactly this reason, but the hook ignored it -- if the
# subprocess's actual OS cwd ever diverged from the project root (a
# sandboxed hook environment, an unusual launch cwd), the hook silently
# read/wrote a different mapping file than the proxy. Symptom in real
# use: the proxy redacted a real IP to a fake one, Claude wrote the
# fake value into a file, and restore-hook returned {"continue": true}
# with no error -- the fake value survived on disk.
# ---------------------------------------------------------------------

def test_restore_hook_anchors_to_event_cwd_not_subprocess_cwd(tmp_path):
    project = _new_project(tmp_path, "projA")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()

    init_result = _run_launcher(project, ["init"])
    assert init_result.returncode == 0, init_result.stderr

    test_result = _run_launcher(project, ["test"])
    assert "PASS: round-trip matches" in test_result.stdout

    mapping = json.loads((project / ".redaction_map.json").read_text())
    fake_ip = next(f for f in mapping if f.startswith("10.99."))
    real_ip = mapping[fake_ip]

    event = {
        "cwd": str(project),
        "tool_name": "Write",
        "tool_input": {"file_path": "out.tf", "content": f'ip = "{fake_ip}"'},
    }
    # Invoke with the subprocess's OWN OS cwd set to a DIFFERENT
    # directory than the project -- only the "cwd" field in the event
    # should determine which mapping file gets used.
    hook_result = _run_launcher(elsewhere, ["restore-hook"], stdin_text=json.dumps(event))
    assert hook_result.returncode == 0, hook_result.stderr

    response = json.loads(hook_result.stdout)
    updated_content = response["hookSpecificOutput"]["updatedInput"]["content"]
    assert real_ip in updated_content, (
        "restore-hook must anchor to the event's 'cwd' field, not the subprocess's "
        "ambient OS cwd, or it silently reads/writes the wrong mapping file"
    )
    assert fake_ip not in updated_content


def test_restore_hook_still_works_when_invoked_from_project_root(tmp_path):
    """Regression guard: the common case (hook subprocess cwd already
    matches the project) must keep working after the cwd-anchoring fix."""
    project = _new_project(tmp_path, "proj")
    _run_launcher(project, ["init"])
    _run_launcher(project, ["test"])

    mapping = json.loads((project / ".redaction_map.json").read_text())
    fake_ip = next(f for f in mapping if f.startswith("10.99."))
    real_ip = mapping[fake_ip]

    event = {
        "cwd": str(project),
        "tool_name": "Write",
        "tool_input": {"file_path": "out.tf", "content": f'ip = "{fake_ip}"'},
    }
    hook_result = _run_launcher(project, ["restore-hook"], stdin_text=json.dumps(event))
    response = json.loads(hook_result.stdout)
    assert real_ip in response["hookSpecificOutput"]["updatedInput"]["content"]


def test_restore_hook_degrades_gracefully_without_cwd_field(tmp_path):
    """Older/hypothetical events without a 'cwd' field must not crash
    -- falls back to whatever the subprocess's ambient cwd is, same as
    before this fix existed."""
    project = _new_project(tmp_path, "proj")
    _run_launcher(project, ["init"])

    event = {"tool_name": "Write", "tool_input": {"file_path": "x", "content": "no fakes here"}}
    hook_result = _run_launcher(project, ["restore-hook"], stdin_text=json.dumps(event))
    assert hook_result.returncode == 0, hook_result.stderr
    assert json.loads(hook_result.stdout) == {"continue": True}
