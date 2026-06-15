# AGENTS.md

This file defines shared project rules for AI coding agents.

## Project Purpose

- Netpp is an educational C++20 networking library/demo.
- Main focus: clarity, correctness, and predictable behavior over premature optimization.
- Core areas: event loop (epoll), TCP/UDP handlers, protocol modules (HTTP, DNS, Echo, Chat).

## Source of Truth

- Respect existing project layout and module boundaries.
- Keep public headers in `include/Netpp/...` and implementation in `src/Netpp/...`.
- Do not introduce new frameworks or large dependencies without explicit request.

## Build and Toolchain

- Use CMake as the build system.
- Preferred configured build dir: `build/`.
- Project standard: C++20.
- Compiler warnings are enabled (`-Wall -Wextra`); new code should compile warning-free.

Typical commands:

```bash
cmake -S . -B build -D CMAKE_BUILD_TYPE=Debug
cmake --build build -j2
ctest --test-dir build
```

## Change Scope Rules

- Make minimal, targeted changes for the requested task.
- Do not refactor unrelated code while solving a focused issue.
- Do not modify generated/build artifacts (`build/`, temporary test outputs) unless explicitly asked.
- Preserve existing public APIs unless API changes are required by the task.

## Code Style and Design

- Follow existing style in touched files (formatting, naming, includes).
- Prefer RAII and clear ownership semantics.
- Use `std::shared_ptr`/`std::unique_ptr` consistently with existing interfaces.
- Keep error handling explicit; log meaningful context for socket and protocol failures.
- Avoid overly clever abstractions; prioritize readable code.

## Networking and Runtime Expectations

- Keep handlers non-blocking and event-loop friendly.
- Avoid blocking calls in hot paths.
- Treat socket lifecycle carefully (register/add, unregister/del, close exactly once).
- Preserve thread/dispatcher safety assumptions when posting callbacks.

## Testing and Validation

- When behavior changes, add or update unit tests under `tests/` whenever practical.
- Run relevant tests after modifications.
- For server/integration behavior, use existing script when needed:

```bash
python3 src/server_test.py
```

## Agent Output Expectations

- Describe what changed and why, briefly and concretely.
- Call out risks, assumptions, and any unverified parts.
- If something cannot be validated locally, state it explicitly.

## Non-Goals

- Do not rewrite architecture without request.
- Do not change licensing, project metadata, or CI workflow unless explicitly requested.
