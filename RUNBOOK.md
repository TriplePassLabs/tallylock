# TallyLock development checks

TallyLock is being built as a standalone CLI. The reviewed product architecture is in PLAN.md, the implementation tasks are in docs/IMPLEMENTATION_PLAN.md and the wire contract is in docs/PROTOCOL.md. No stable CLI release is available yet.

For contributors using an isolated development environment on Linux with Python 3.11, 3.12 or 3.13:

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --timeout 30 --retries 2 'setuptools>=77' wheel '.[dev]'
python -m pip check
python -m pytest
python -m build --no-isolation
python tools/check_distribution.py --dist dist --source-root .
```

Do not run batch builds or tests in a resource-constrained shared editor environment. Use a separate bounded worker there. Test evidence must distinguish local integrity checks, synthetic timestamp fixtures, live calendar submissions and independently trusted chain evidence.

For a clean installed-artifact check, make a new virtual environment for each artifact, install it with dependencies, run `python -m pip check` there, then run `python tools/check_install.py --python /absolute/path/to/venv/bin/python --expected-version 0.1.0a3` from the source tree. Repeat for the wheel and sdist. The install checker runs its CLI flow outside the checkout and rejects socket operations in those CLI commands through a Python audit hook. It does not supply an OS-level network namespace. CI runs the full test suite and both clean-install checks on Python 3.11 through 3.13; its workflow is in `.github/workflows/ci.yml`.

The runtime dependency inventory, including installed metadata and bundled-license evidence, is in [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md). Recheck resolved versions and license evidence when preparing a release.

The generic example is examples/basic/. Protocol and verifier changes need adversarial vectors and independent review. Research projects are external consumers: product code and installation must not depend on them.
