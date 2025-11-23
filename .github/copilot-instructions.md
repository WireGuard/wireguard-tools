<!-- GitHub Copilot / AI agent instructions for wireguard-tools -->

# Purpose

Concise, action-first guidance for AI coding agents to be productive in
`wireguard-tools`. Focus: where to change code, how to build/test, and
project conventions that differ from typical C projects.

# Big picture

- Repo provides userspace tooling for WireGuard: the `wg(8)` CLI and
  `wg-quick(8)` helper scripts. Primary code: `src/`. Platform specifics live
  under `uapi/` (kernel headers) and `wincompat/` (Windows portability).
- Major areas: `src/` (C CLI tools), `wg-quick/` (shell helpers), `uapi/`,
  `completion/`, `systemd/`, `man/`, and `contrib/` + `external-tests/`.

# Quick start (commands you'll use most)

- Build: `cd src && make`
- Verbose build/debug: `cd src && make V=1 DEBUG=yes`
- Install for packaging tests: `make install PREFIX=/usr DESTDIR=<dest> WITH_WGQUICK=yes WITH_BASHCOMPLETION=yes`
- Static analysis: `cd src && make check` (runs `scan-build` if available)
- Cross-build for Windows: set `PLATFORM=windows` (Makefile will use `wincompat/`).

# Code change conventions (important)

- Adding a C source: place under `src/` — the `src/Makefile` builds `*.c`
  by default. Keep flags consistent with `CFLAGS` in `src/Makefile`.
- Platform-specific headers go in `uapi/<platform>/` and are added with
  `-isystem uapi/$(PLATFORM)`; do not diverge from kernel WireGuard headers
  without coordinating upstream kernel changes.
- When adding runtime files (scripts, manpages, completion, systemd units),
  update the `install` target in `src/Makefile` so packaging includes them.
- Prefer existing helpers (`ipc-*.h`, `netlink.h`) for IPC and netlink logic.

# Files to read first (high value)

- `src/Makefile` — build, platform detection, install flags (`WITH_WGQUICK`,
  `WITH_BASHCOMPLETION`, `WITH_SYSTEMDUNITS`).
- `src/wg.c`, `src/setconf.c`, `src/show.c` — core CLI behavior and parsing.
- `wg-quick/` scripts — show how configs are consumed and expected runtime
  behavior for `wg-quick`.
- `uapi/` — kernel/user API headers (keeps user tooling in sync with kernel).

# Testing / validation checklist before PR

- Run `cd src && make V=1` to reproduce compile issues.
- Run `cd src && make check` if changing parsing, memory-handling, or IPC.
- If adding files that affect packaging, run `make install DESTDIR=<tmp>` and
  verify installed layout.

# Notes on portability & packaging

- Minimal dependencies: project targets portability and a plain libc.
- Keep changes small and portable. Avoid introducing new heavy deps.

# PR tips for reviewers

- Include the minimal build and install commands you used to verify the
  change. Show `make V=1` output if build flags or toolchain changes were
  required.
- If you changed `uapi/`, state why it must differ from upstream kernel
  headers and include references.

# If you're stuck

- Read `README.md` and `src/Makefile` first. If build errors persist, paste
  `make V=1` output and relevant `gcc/clang` errors into the PR description.

---
If you'd like, I can (a) shorten or expand any section, (b) add a short
walkthrough for adding a CLI flag in `wg.c`, or (c) include a sample PR
checklist. Which would you prefer?

## Walkthrough — Add a small CLI flag to an existing subcommand

Example: add a simple `--example-flag` to the `show` subcommand.

- Files to edit: `src/show.c` (subcommand implementation) and, if needed,
  tests or `man/` pages.
- Typical steps:
  1. Locate the subcommand entry in `src/wg.c` (the `subcommands[]` table lists
    available subcommands and their `*_main` functions; `show` maps to `show_main`).
  2. Open `src/show.c` and find `show_main` — it handles argc/argv for `show`.
  3. Add minimal flag parsing near the top of `show_main`. This project uses
    simple `argv` checks rather than a heavy option parser; follow existing
    patterns (see checks for `argc` and `argv[1]` already in `show_main`).
  4. Implement the behavior (set a local `bool` or configuration struct and
    branch later in the printing functions such as `pretty_print` or
    `ugly_print`).
  5. Build and run the subcommand locally: `cd src && make V=1 && ./wg show --help`.
  6. Run `make check` if you changed parsing or memory handling.

- Minimal illustrative code sketch (adapt to project's helpers):

```c
// in src/show.c, inside show_main before printing
bool example_flag = false;
for (int i = 1; i < argc; ++i) {
   if (!strcmp(argv[i], "--example-flag")) {
      example_flag = true;
      // optionally remove the consumed arg or shift argv
   }
}
// Later, in pretty_print or dump_print, use `example_flag` to alter output
```

Keep changes small and follow existing formatting and error handling patterns.
