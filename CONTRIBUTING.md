# Contributing to t-ron

Thank you for your interest in contributing to t-ron. This document covers the
development workflow, code standards, and project conventions.

## Development Workflow

1. **Fork** the repository on GitHub.
2. **Create a branch** from `main` for your work.
3. **Make your changes**, ensuring all checks pass.
4. **Open a pull request** against `main`.

## Prerequisites

- Rust toolchain (MSRV: **1.89**)
- `cargo-deny` — supply chain checks
- `cargo-llvm-cov` — code coverage (optional)

## Makefile Targets

| Target          | Description                                      |
| --------------- | ------------------------------------------------ |
| `make check`    | Run fmt + clippy + test (the full suite)         |
| `make fmt`      | Format code with `cargo fmt`                     |
| `make clippy`   | Lint with `cargo clippy`                         |
| `make test`     | Run the test suite                               |
| `make audit`    | Security audit with `cargo audit`                |
| `make deny`     | Audit dependencies with `cargo deny`             |
| `make coverage` | Generate code coverage report                    |
| `make doc`      | Build rustdoc documentation                      |

Before opening a PR, run `make check` to verify everything passes.

## Adding a New Security Check

1. Create `src/module.rs` with your implementation.
2. Add the module to `src/lib.rs`.
3. Wire the check into `TRon::check()` in `lib.rs` at the appropriate pipeline
   stage.
4. Add unit tests in the module file under `#[cfg(test)]`.
5. Update the architecture overview in `docs/architecture/overview.md`.
6. Update `README.md` features list.

## Code Style

- Run `cargo fmt` before committing. All code must be formatted.
- `cargo clippy -D warnings` must pass with no warnings.
- All public items (functions, structs, enums, traits, type aliases) must have
  doc comments.
- Keep functions focused and testable.
- Security checks should fail closed — when in doubt, deny.

## Testing

- Unit tests go in the module file under `#[cfg(test)]`.
- Integration tests through `SecurityGate` are preferred for end-to-end
  verification.
- All new security checks require tests for both detection and false-positive
  avoidance.
- Verify that the libro chain stays intact after your changes
  (`verify_chain()`).

## License

t-ron is licensed under **GPL-3.0**. All contributions must be compatible
with this license. By submitting a pull request, you agree that your
contribution is licensed under the same terms.
