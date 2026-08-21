# uv: the standard for Python

Every PSD Python repo uses [uv](https://docs.astral.sh/uv/) for dependencies,
virtual environments, and running code. Not pip, not poetry, not conda.

Why: uv gives Python what JavaScript always had — a real lockfile (`uv.lock`) — so
CI, your laptop, and the server all install byte-identical dependencies. It also
manages Python versions and virtual environments itself, so installs behave the
same on every machine.

## Daily commands

| You used to run | Now run |
|---|---|
| `pip install -r requirements.txt` | `uv sync` |
| `pip install <pkg>` | `uv add <pkg>` |
| `python script.py` | `uv run script.py` |
| `pytest` | `uv run pytest` |
| `python -m venv .venv` and activate | Nothing — `uv run` handles the environment |

To install uv, run `curl -LsSf https://astral.sh/uv/install.sh | sh` on macOS and
Linux, or `powershell -c "irm https://astral.sh/uv/install.ps1 | iex"` on Windows.
On macOS with Homebrew: `brew install uv`.

## Convert an existing repo

1. On a branch, if the repo only has `requirements.txt`, create `pyproject.toml`
   from it:

   ```
   uv init --bare
   uv add -r requirements.txt
   ```

   Keep every version constraint exactly as it was — a conversion PR must not
   change versions.
2. Put dev-only tools, such as pytest and ruff, in the dev group:

   ```
   uv add --dev pytest ruff
   ```

3. Generate and commit the lockfile:

   ```
   uv lock
   ```

4. Before you delete `requirements.txt`, check what reads it — Dockerfiles, deploy
   scripts, `setup.bat`, cloud platforms. Update those consumers to use `uv sync`.
   If something must keep consuming a requirements file, generate the file from the
   lockfile so it can't drift:

   ```
   uv export --format requirements-txt > requirements.txt
   ```

5. Delete `Pipfile` and `poetry.lock` if present.
6. Verify from a fresh clone: run `uv sync`, run the full test suite with
   `uv run pytest`, and confirm the app starts.
7. Open a PR. In the description, state that you carried the constraints over
   unchanged — or list exactly what resolved differently and why.

For one-off scripts with no repo and no `pyproject.toml`, use
[PEP 723 inline metadata](https://docs.astral.sh/uv/guides/scripts/): declare
dependencies in a comment block at the top of the script and run it with
`uv run script.py`.

## Check for an existing conversion PR

Many repos received a conversion PR from the standards rollout, labeled
`runtime-standard-wave`. If your repo has one open, review and merge that PR instead
of starting over.
