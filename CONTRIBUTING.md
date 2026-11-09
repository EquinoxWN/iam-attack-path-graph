# Contributing

Thanks for helping. This is a Python project; issues and pull requests are welcome.

## Set up and check your change

Needs Python 3.11+. Caches and virtual environments stay in git-ignored folders inside the repo.

```bash
make setup   # install the package and dev tools
make lint    # ruff, ruff format --check, mypy --strict
make test    # full test suite
make audit   # known-vulnerability check (as in CI)
make demo    # effective permissions of the lab account
```

A pull request is ready when `make lint` and `make test` pass and CI is green.

## Guidelines

- Keep each change focused; explain the problem it solves in the pull request.
- An evaluator change needs a test that cites the AWS behaviour it implements, and the lab
  account's expected answers in `tests/test_effective.py` must still hold (or be changed on purpose).
- Fixtures use invented names, account ID 123456789012 and `EXAMPLE-NOT-A-SECRET`; never real data.
- Significant design changes need an ADR in `docs/adr/` (copy `0001` for the format).
- Keep function comments to one short phrase; let names and tests explain the rest.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your work is released under the [MIT License](LICENSE).
