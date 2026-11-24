# Contributing

Thanks for considering a contribution. This project is a local privacy proxy
for DeepSeek Harness (DSH); it is Windows-first and intentionally uses the
Python standard library only.

[Русский](CONTRIBUTING.md) · [English](CONTRIBUTING.en.md)

## Development setup

- Windows 10/11, Python 3.12+.
- No third-party runtime dependencies. Do not add `pip install` requirements
  to the proxy or admin path.
- The audit can use `python -m redactrail.review`; reading zstd sessions
  needs Python 3.14 or `zstd` in `PATH`.

```powershell
copy policy.example.json policy.json   # local policy, never commit it
python -m unittest discover -s tests -t .
powershell -ExecutionPolicy Bypass -File scripts/test.ps1
```

`scripts/test.ps1` runs the tests and the detector benchmark gate. A pull
request must keep it green.

## Tests and fixtures

- **Synthetic data only.** Do not paste real names, phone numbers, addresses,
  keys or session logs into tests, benchmark fixtures or screenshots.
- New detection behavior needs a test in `tests/corpus/` or `tests/test_entities.py`.
- New proxy behavior needs an end-to-end test in `tests/test_proxy.py`.
- Use `policy.example.json` for tests; `policy.json` is local and gitignored.

## Code style

- Standard library only; type hints on public functions.
- Keep detection deterministic and fail-closed: an unexpected block shape must
  be rejected, not forwarded.
- Do not log values. Hashes, classes and lengths only.
- Update `CHANGELOG.md` for user-visible changes.

## Pull request checklist

- [ ] tests added or updated;
- [ ] `scripts/test.ps1` is green;
- [ ] no real personal data in code, fixtures, docs or screenshots;
- [ ] no new runtime dependencies;
- [ ] CHANGELOG entry;
- [ ] description explains the threat model impact.

## Reporting bugs

Use the issue template. For security problems follow [SECURITY.md](SECURITY.md)
and report privately.

## Code of conduct

Participation is covered by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
([Russian translation](docs/code-of-conduct.ru.md)).
