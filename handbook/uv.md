# uv — the standard for Python

Every PSD Python repo uses [uv](https://docs.astral.sh/uv/) for dependencies,
virtual environments, and running code. Not pip, not poetry, not conda.

**Why:** uv gives Python what JS always had — a real lockfile (`uv.lock`) so CI,
your laptop, and the server all install byte-identical dependencies. It also
manages Python versions and virtualenvs itself, so "works on my machine" mostly
stops being a sentence anyone says.

## Daily commands

| You used to run | Now run |
|---|---|
| `pip install -r requirements.txt` | `uv sync` |
| `pip install <pkg>` | `uv add <pkg>` |
| `python script.py` | `uv run script.py` |
| `pytest` | `uv run pytest` |
| `python -m venv .venv` + activate | nothing — `uv run` handles the environment |

Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh` (macOS/Linux) or
`powershell -c "irm https://astral.sh/uv/install.ps1 | iex"` (Windows).
macOS with Homebrew: `brew install uv`.

## Converting an existing repo

1. On a branch: create `pyproject.toml` if the repo only has `requirements.txt`:

   ```
   uv init --bare
   uv add -r requirements.txt
   ```

   Keep every version constraint exactly as it was — conversion PRs should not
   change versions.
2. Put dev-only tools (pytest, ruff, etc.) in the dev group:
   `uv add --dev pytest ruff`
3. `uv lock` writes `uv.lock`. Commit it.
4. **Before deleting `requirements.txt`, check what reads it** — Dockerfiles,
   deploy scripts, `setup.bat`, cloud platforms. Update them to `uv sync`, or if
   something must keep consuming a requirements file, generate it from the
   lockfile so it can't drift:

   ```
   uv export --format requirements-txt > requirements.txt
   ```

5. Delete `Pipfile`/`poetry.lock` if present.
6. Verify: fresh clone, `uv sync`, `uv run pytest` — full suite, and confirm the
   app actually starts.
7. Open a PR; state in the description that constraints were carried over
   unchanged (or list exactly what resolved differently and why).

**One-off scripts** (no repo, no pyproject): use
[PEP 723 inline metadata](https://docs.astral.sh/uv/guides/scripts/) — declare
dependencies in a comment block at the top and run with `uv run script.py`.

## Already converted for you?

Many repos received a conversion PR from the standards rollout (label
`runtime-standard-wave`). If your repo has one open, review and merge that instead
of starting over.
