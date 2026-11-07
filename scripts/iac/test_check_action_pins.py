# ABOUTME: Tests for check_action_pins.py: every SHA-pinned `uses:` must exist at
# ABOUTME: that SHA and must not declare a Node runtime GitHub has removed.
"""Offline tests. A fake fetcher stands in for raw.githubusercontent.com."""
import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).with_name("check_action_pins.py")
spec = importlib.util.spec_from_file_location("check_action_pins", SCRIPT)
pins = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pins)

SHA = "a" * 40


def fetcher(files):
    """files maps 'owner/repo/sha/path' to text; anything else is missing."""
    def fetch(owner_repo, sha, path):
        return files.get(f"{owner_repo}/{sha}/{path}")
    return fetch


def workflow(tmp_path, *uses):
    steps = "\n".join(f"      - uses: {u}" for u in uses)
    f = tmp_path / "wf.yml"
    f.write_text(f"jobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n{steps}\n")
    return f


def test_missing_subdirectory_at_the_pinned_sha_fails(tmp_path):
    f = workflow(tmp_path, f"infracost/actions/comment@{SHA} # v5")
    problems = pins.check([f], fetcher({f"infracost/actions/{SHA}/setup/action.yml": "runs:\n  using: node24\n"}))
    assert len(problems) == 1
    assert "infracost/actions/comment" in problems[0]
    assert "no action.yml" in problems[0]


def test_node20_action_fails(tmp_path):
    f = workflow(tmp_path, f"actions/checkout@{SHA} # v4")
    problems = pins.check([f], fetcher({f"actions/checkout/{SHA}/action.yml": "runs:\n  using: 'node20'\n"}))
    assert problems == [f"{f}: actions/checkout@{SHA} declares runs.using node20, which GitHub-hosted runners no longer ship"]


def test_node24_composite_docker_and_action_yaml_pass(tmp_path):
    f = workflow(tmp_path, f"a/node@{SHA}", f"b/comp@{SHA}", f"c/dock@{SHA}", f"d/yaml/sub@{SHA}")
    files = {
        f"a/node/{SHA}/action.yml": "runs:\n  using: node24\n",
        f"b/comp/{SHA}/action.yml": "runs:\n  using: composite\n",
        f"c/dock/{SHA}/action.yml": "runs:\n  using: docker\n",
        f"d/yaml/{SHA}/sub/action.yaml": "runs:\n  using: \"node24\"\n",
    }
    assert pins.check([f], fetcher(files)) == []


def test_reusable_workflow_ref_must_exist_at_sha(tmp_path):
    good = f"PSD401/.github/.github/workflows/reusable-iac-checks.yml@{SHA}"
    bad = f"PSD401/.github/.github/workflows/gone.yml@{SHA}"
    f = tmp_path / "caller.yml"
    f.write_text(f"jobs:\n  a:\n    uses: {good}\n  b:\n    uses: {bad}\n")
    files = {f"PSD401/.github/{SHA}/.github/workflows/reusable-iac-checks.yml": "on: workflow_call\n"}
    problems = pins.check([f], fetcher(files))
    assert len(problems) == 1
    assert "gone.yml" in problems[0]


def test_local_docker_and_unpinned_refs_are_not_fetched(tmp_path):
    f = workflow(tmp_path, "./local-action", "docker://alpine:3", "actions/checkout@v4")
    calls = []

    def fetch(*args):
        calls.append(args)
        return None
    assert pins.check([f], fetch) == []
    assert calls == []


def test_each_distinct_pin_is_fetched_once(tmp_path):
    f = workflow(tmp_path, f"actions/checkout@{SHA}", f"actions/checkout@{SHA}")
    calls = []

    def fetch(owner_repo, sha, path):
        calls.append(path)
        return "runs:\n  using: node24\n"
    assert pins.check([f], fetch) == []
    assert calls == ["action.yml"]


def test_live_fetch_sends_github_token_when_set(monkeypatch):
    """Internal and private repos 404 on raw.githubusercontent.com without a token."""
    seen = {}

    class Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"runs:\n  using: node24\n"

    def fake_urlopen(req, timeout):
        seen["auth"] = req.get_header("Authorization")
        seen["url"] = req.full_url
        return Resp()
    monkeypatch.setattr(pins.urllib.request, "urlopen", fake_urlopen)
    monkeypatch.setenv("GITHUB_TOKEN", "t0k")
    assert pins.fetch_raw("PSD401/x", SHA, "action.yml").startswith("runs:")
    assert seen["auth"] == "token t0k"
    assert seen["url"] == f"https://raw.githubusercontent.com/PSD401/x/{SHA}/action.yml"


def test_iac_tests_workflow_runs_the_checker_on_this_repos_workflows():
    import yaml
    root = SCRIPT.parents[2]
    wf = yaml.safe_load((root / ".github/workflows/iac-tests.yml").read_text())
    runs = [s.get("run", "") for job in wf["jobs"].values() for s in job.get("steps", [])]
    cmd = next((r for r in runs if "scripts/iac/check_action_pins.py" in r), None)
    assert cmd, "iac-tests.yml should run scripts/iac/check_action_pins.py"
    assert ".github/workflows/*.yml" in cmd
    assert "workflow-templates/*.yml" in cmd
    paths = wf.get("on", wf.get(True))["pull_request"]["paths"]  # PyYAML reads `on:` as True
    assert "scripts/iac/**" in paths
