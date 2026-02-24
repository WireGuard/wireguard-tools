<!-- GitHub Copilot / AI agent instructions for wireguard-tools -->

# Purpose

Short, actionable guidance for AI coding agents to be immediately productive in
this repository. Focus on how the project is structured, build/test/debug
workflows, and concrete file examples you should read before changing code.

# Big picture

- **What this repo is**: userspace tooling for WireGuard: the `wg(8)` CLI and
  `wg-quick(8)` helper scripts. Primary code lives in `src/` and platform
  specifics under `uapi/` and `wincompat/`.
- **Major components**:
  - `src/` — main C sources (`wg.c`, `setconf.c`, `show.c`, etc.) and `src/Makefile`.
  - `wg-quick/` — platform-specific shell scripts (bash) used by install.
  - `uapi/` — platform-specific kernel/user API headers included at build time.
  - `contrib/` and `external-tests/` — sample integrations and language bindings.
  - `wincompat/` — compatibility layer and resources for Windows builds.

# What to read first (examples)

- `README.md` — project overview and canonical build/install commands.
- `src/Makefile` — most important: how compilation, platform detection, and
  installation variables work (`PREFIX`, `WITH_WGQUICK`, `WITH_BASHCOMPLETION`).
- `src/wg.c`, `src/setconf.c`, `src/show.c` — core CLI behavior and parsing.
- `wg-quick/` — how the quick helper expects configuration files.
- `uapi/linux/` — shows kernel-compatible headers used when compiling.

# Build, test and debug (concrete commands)

- Build the tools (recommended):

  `cd src && make`

- Install (honors packaging env vars):

  `make install PREFIX=/usr DESTDIR=... WITH_WGQUICK=yes WITH_BASHCOMPLETION=yes`

- Useful Makefile knobs:
  - `V=1` — disable pretty short messages and print full compiler/linker commands.
  - `DEBUG=yes` — compile with `-g` for debugging symbols.
  - `PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')` is auto-detected.

- Static analysis:

  `cd src && make check`  # runs `scan-build` if available

- Windows cross-build: `wincompat/` files are used when `PLATFORM=windows`.
  The Makefile sets `CC` for mingw (`x86_64-w64-mingw32-clang`) when building
  for Windows; inspect `wincompat/` for resource and manifest handling.

# Project-specific conventions & patterns

- Minimal dependencies: the top-level `README.md` states "no dependencies other
  than a good C compiler and a sane libc." Expect simple, portable C patterns.
- Platform headers: `src/Makefile` adds `-isystem uapi/$(PLATFORM)` when that
  directory exists. Prefer adding platform-specific headers under `uapi/`.
- Packaging variables and conditional installs are controlled in `src/Makefile`.
  When adding files that should be packaged, update `install` target there.
- Shell helpers: `wg-quick` is intentionally a small, opinionated bash script;
  changes to interface/flags must remain compatible with it.

# Integration points & external interfaces

- Kernel/user API: code relies on headers in `uapi/` to match kernel wireguard
  definitions — don't diverge without coordinating kernel changes.
- System integration: systemd unit templates are in `systemd/`; `install`
  target will optionally install them if `WITH_SYSTEMDUNITS` is enabled.
- Completion scripts are under `completion/` and are installed when
  `WITH_BASHCOMPLETION=yes`.
- `contrib/embeddable-wg-library/` contains an example of embedding wireguard
  logic into other languages; use it as a reference for integrations.

# Testing & external test harnesses

- Look at `external-tests/` for example consumers in Go, Rust, Python and
  Haskell. These show how others interact with the CLI or wireguard APIs.
- Fuzzing harness is in `fuzz/` with its own `Makefile` — follow that
  directory's README before changing the fuzz targets.

# Helpful patterns and examples for edits

- When adding a new source file to `src/`, add it to the wildcard `*.c` pattern
  in `src/Makefile` (it already builds all `*.c`). Keep compilation flags
  consistent with the existing `CFLAGS` defined there.
- To preserve portable behavior, prefer using existing helpers in `ipc-*.h`
  and `netlink.h` rather than adding custom platform IPC code.

# What an AI agent should do when making a change

1. Read `src/Makefile` and the relevant `uapi/<platform>/` headers.
2. Run `cd src && make V=1` locally to verify build commands and locate
   compile-time failures.
3. Update `install` target only if adding runtime files (scripts, manpages,
   completions, systemd units) and test installation locally using `DESTDIR`.
4. Run `make check` if the change touches memory/undefined behavior sensitive
   code and static analysis is available.

# Questions / feedback

If any of these sections are unclear or you'd like more examples (e.g. a
short walkthrough of adding a new CLI flag in `wg.c`), tell me which area to
expand and I'll update this file.
