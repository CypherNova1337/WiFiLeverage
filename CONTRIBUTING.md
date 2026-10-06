# Contributing

Thanks for your interest in WiFiLeverage.

## Ground rules

- Only test against networks you own or are explicitly authorized to assess.
  Do not submit output, captures or screenshots taken from networks you do not
  have permission to test.
- Keep new probing behaviour **scope-aware**: anything that sends packets must
  route its targets through `Scope` so excluded networks are never touched.
- Passive-by-default: active modules must be gated behind `ctx.active`.

## Development

```bash
git clone https://github.com/CypherNova1337/WiFiLeverage
cd WiFiLeverage
pip install -e ".[dev]"
pytest
```

## Adding a module

1. Subclass `wifileverage.modules.base.Module`, set `name`, `phase`
   (`PASSIVE`/`ACTIVE`) and `description`, implement `run(ctx)`.
2. Keep parsing logic as pure static methods so it can be unit-tested without
   network access or privileges (see the existing modules for the pattern).
3. Register it in `wifileverage/modules/__init__.py` and wire it into a profile
   or phase in `wifileverage/runner.py`.
4. Add tests under `tests/`.

## Style

- Standard library first; the only runtime dependency is PyYAML.
- Run `pytest` before opening a PR.
