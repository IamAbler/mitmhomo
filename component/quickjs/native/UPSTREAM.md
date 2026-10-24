# Vendored QuickJS source

- Project: QuickJS by Fabrice Bellard and Charlie Gordon.
- Release: `2026-06-04` (`VERSION` contains the same value).
- Release date: 2026-06-04.
- Official page: <https://bellard.org/quickjs/>.
- Source archive: <https://bellard.org/quickjs/quickjs-2026-06-04.tar.xz>.
- Archive SHA-256: `b376e839b322978313d929fd20663b11ba58b75df5a46c126dd19ea2fa70ad2a`.
- License: MIT; the upstream `LICENSE` and source copyright notices are retained.

The 621,500-byte archive was downloaded twice over HTTPS from the official
QuickJS site; both copies had the recorded SHA-256 and compared byte-for-byte.
`xz -t` and `tar -tJf` both passed. The official site does not publish an
archive checksum, so the recorded SHA-256 is the locally computed pin, not an
upstream signature. `SHA256SUMS` records the exact vendored files for future
comparison.

## Included upstream files

The vendored subset is exactly the code needed for the QuickJS core library:

- `quickjs.c`, `quickjs.h`, `quickjs-atom.h`, `quickjs-opcode.h`, `list.h`
- `dtoa.c`, `dtoa.h`
- `libregexp.c`, `libregexp.h`, `libregexp-opcode.h`
- `libunicode.c`, `libunicode.h`, `libunicode-table.h`
- `cutils.c`, `cutils.h`
- `LICENSE`, `VERSION`, `Changelog`

`quickjs-libc.c`, the command line tools, generated executables, test data,
examples, and documentation binaries are not built into the adapter. The
upstream C and header files above are copied byte-for-byte from the pinned
archive. No upstream C source patch is carried.

## Build integration

Go's cgo compiler only discovers C source files in the Go package directory;
it does not recursively compile `native/`. The package-root `qjs_*.c` files
are small, tagged translation units that include one upstream C source each.
They keep upstream files together under `native/`, preserve separate C
translation units, and avoid checked-in static libraries or build-time network
downloads. The tag is `quickjs && cgo`; ordinary builds select the explicit
unavailable stub.

The build uses GNU C11 because upstream uses GNU `asm` syntax, `_GNU_SOURCE`,
the release string as `CONFIG_VERSION`, and the upstream `-fwrapv` behavior via
a GCC `optimize("wrapv")` pragma in each translation unit. The bridge links
`libm` and `pthread`, matching the upstream Makefile's core link requirements.
Windows adds upstream's `__USE_MINGW_ANSI_STDIO` compatibility define. The
supported Windows CGO compiler is MinGW-w64 GCC. The initial local validation
environment did not have that compiler; later Windows runner results are
recorded under M6.1 acceptance below. Those runner checks do not replace
clean-system distribution validation.

## License and update policy

QuickJS's official site identifies the distribution as MIT licensed. The
upstream `LICENSE` is included; individual vendored headers and C sources also
retain their upstream copyright/license comments. The core inputs contain
QuickJS, libregexp, libunicode, dtoa, and cutils; no additional third-party C
library was introduced.

For an update, select a dated official release, download only from
`bellard.org`, verify archive format and contents, compute and review the
archive SHA-256, diff the selected source and license files, inspect the
release changelog and security fixes, then update `VERSION`, `SHA256SUMS`, and
this record in one reviewable change. Keep upstream code unmodified where
possible. Any required source fix must be a separate, named patch with a
focused diff and tests. Re-run the Linux and Windows CGO matrix, allocator,
interrupt, Job Queue, and native sanitizer checks before accepting an update.
Builds must consume the checked-in vendor tree and must never download source
at build time.

## M6.1 acceptance and distribution boundary

M6.1 and the M6.1-D static-link validation both received human acceptance as
PASS on 2026-10-24. The final QuickJS CI run is
[#6](https://github.com/IamAbler/mitmhomo/actions/runs/40054989816); the final
M6.1-D run is [#3](https://github.com/IamAbler/mitmhomo/actions/runs/40054989950).
Both ran on `validation/m61-quickjs-ci` at
`51cad112f60df61431cf00fe229958c2a9d78976`.

The earlier failed QuickJS CI run remains recorded in the M6.1 remote
validation report and in GitHub Actions history. Passing this infrastructure
milestone does not mean the current main program uses QuickJS: the main package
does not import `component/quickjs`, and the `quickjs` tagged main-program
build is a build-compatibility check. Clean-system Windows validation, Linux
arm64 validation, and final distribution of the integrated program remain
M6.10 acceptance work.
