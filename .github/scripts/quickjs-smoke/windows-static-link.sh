#!/usr/bin/env bash
set -euo pipefail

artifact_dir="artifacts/m61d-static/windows-amd64"
mkdir -p "$artifact_dir"

if [[ "${GOOS:-}" != "windows" || "${GOARCH:-}" != "amd64" || "${CGO_ENABLED:-}" != "1" || "${CC:-}" != "gcc" ]]; then
	printf 'Unexpected build environment: GOOS=%s GOARCH=%s CGO_ENABLED=%s CC=%s\n' \
		"${GOOS:-}" "${GOARCH:-}" "${CGO_ENABLED:-}" "${CC:-}" >&2
	exit 1
fi

printf 'go: %s\n' "$(go version)"
printf 'gcc target: %s\n' "$(gcc -dumpmachine)"
gcc --version | head -n 1
ld --version | head -n 1

inspect_archive() {
	local name="$1"
	local stem="${name//./-}"
	local raw_path archive_path
	local members_file="$artifact_dir/${stem}-members.txt"
	local object_file="$artifact_dir/${stem}-objects.txt"
	local symbols_file="$artifact_dir/${stem}-pthread-symbols.txt"
	local dll_id_file="$artifact_dir/${stem}-dlltool-identify.txt"

	raw_path="$(gcc -print-file-name="$name" | tr -d '\r')"
	printf '\nARCHIVE_CANDIDATE %s\nGCC_LOOKUP=%s\n' "$name" "$raw_path"
	if [[ "$raw_path" == "$name" ]]; then
		printf 'ARCHIVE_STATUS=NOT_FOUND\n'
		return
	fi
	archive_path="$(cygpath -u "$raw_path")"
	if [[ ! -f "$archive_path" ]]; then
		printf 'ARCHIVE_STATUS=PATH_NOT_FOUND\n'
		return
	fi
	printf 'ARCHIVE_PATH=%s\n' "$archive_path"
	file "$archive_path" || true
	sha256sum "$archive_path" || true
	if ar t "$archive_path" >"$members_file" 2>&1; then
		printf 'ARCHIVE_MEMBER_COUNT=%s\n' "$(wc -l < "$members_file" | tr -d ' ')"
	else
		printf 'ARCHIVE_MEMBERS=FAILED\n'
	fi
	if objdump -f "$archive_path" >"$object_file" 2>&1; then
		printf 'ARCHIVE_OBJECT_HEADERS=%s\n' "$object_file"
	else
		printf 'ARCHIVE_OBJECT_HEADERS=FAILED\n'
	fi
	if nm -A --defined-only "$archive_path" 2>/dev/null \
		| grep -E 'pthread_(mutex_lock|cond_wait|cond_timedwait)' >"$symbols_file"; then
		printf 'PTHREAD_SYMBOLS_FOUND=yes\n'
	else
		printf 'PTHREAD_SYMBOLS_FOUND=no\n'
	fi
	if command -v dlltool >/dev/null 2>&1; then
		if dlltool -I "$archive_path" >"$dll_id_file" 2>&1; then
			printf 'DLLTOOL_IDENTIFIED_IMPORT_TARGET=%s\n' "$(tr -d '\r\n' < "$dll_id_file")"
		else
			printf 'DLLTOOL_DID_NOT_IDENTIFY_IMPORT_TARGET\n'
		fi
	else
		printf 'DLLTOOL=NOT_FOUND\n'
	fi
}

inspect_archive libwinpthread.a
inspect_archive libpthread.a
inspect_archive libwinpthread.dll.a

is_windows_system_dll() {
	local dll="${1,,}"
	case "$dll" in
		api-ms-win-*.dll|ext-ms-win-*.dll|advapi32.dll|bcrypt.dll|bcryptprimitives.dll|cfgmgr32.dll|combase.dll|comdlg32.dll|comctl32.dll|crypt32.dll|cryptbase.dll|cryptnet.dll|dnsapi.dll|gdi32.dll|httpapi.dll|iphlpapi.dll|kernel32.dll|kernelbase.dll|msvcrt.dll|mswsock.dll|ncrypt.dll|ncryptsslp.dll|netapi32.dll|ntdll.dll|nsi.dll|ole32.dll|oleaut32.dll|powrprof.dll|psapi.dll|rpcrt4.dll|secur32.dll|setupapi.dll|shell32.dll|shlwapi.dll|ucrtbase.dll|user32.dll|userenv.dll|version.dll|winhttp.dll|wininet.dll|winmm.dll|wintrust.dll|ws2_32.dll|wtsapi32.dll)
			return 0
			;;
		*)
			return 1
			;;
	esac
}

inspect_pe() {
	local exe="$1"
	local stem="$2"
	local require_static="${3:-false}"
	local direct_file="$artifact_dir/${stem}-direct-imports.txt"
	local delay_file="$artifact_dir/${stem}-delay-imports.txt"
	local strict_log="$artifact_dir/${stem}-strict-pe-check.log"
	local names_file="$artifact_dir/${stem}-all-imports.txt"
	local unknown=0

	if ! GO111MODULE=off go run ./.github/scripts/pecheck "$exe" "$direct_file" "$delay_file" >"$strict_log" 2>&1; then
		cat "$strict_log" >&2
		return 1
	fi
	cat "$strict_log"
	file "$exe"
	objdump -f "$exe"

	cat "$direct_file" "$delay_file" | sort -fu >"$names_file"
	while IFS= read -r dll; do
		[[ -n "$dll" ]] || continue
		if is_windows_system_dll "$dll"; then
			printf 'WINDOWS_SYSTEM_DLL %s\n' "$dll"
		else
			printf 'NON_SYSTEM_DLL %s\n' "$dll"
			unknown=1
		fi
	done <"$names_file"
	if [[ "$require_static" != "true" ]]; then
		printf 'BASELINE_PE_CHECK=PASS (runtime-only DLLs are recorded for comparison)\n'
		return 0
	fi
	if grep -Fxiq 'libwinpthread-1.dll' "$names_file"; then
		printf 'WINPTHREAD_DLL_IMPORT=FAIL\n'
		return 1
	fi
	if [[ "$unknown" != "0" ]]; then
		printf 'THIRD_PARTY_DLL_CHECK=FAIL\n'
		return 1
	fi
	printf 'PE_ARCH_AND_IMPORT_CHECK=PASS\n'
}

run_isolated() {
	local exe="$1"
	local script_path windows_exe windows_root
	script_path="$(cygpath -w .github/scripts/quickjs-smoke/run-isolated.ps1)"
	windows_exe="$(cygpath -w "$exe")"
	windows_root="$(cygpath -w "${RUNNER_TEMP:-$PWD}")"
	powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$script_path" \
		-Executable "$windows_exe" -IsolationRoot "$windows_root"
}

build_baseline() {
	local exe="$artifact_dir/quickjs-smoke-baseline.exe"
	local log="$artifact_dir/quickjs-smoke-baseline-build.log"
	if ! go build -x -tags quickjs -o "$exe" ./.github/scripts/quickjs-smoke >"$log" 2>&1; then
		cat "$log" >&2
		return 1
	fi
	printf 'BASELINE_BUILD=PASS\n'
	inspect_pe "$exe" baseline false
	"$exe"
}

try_static_build() {
	local name="$1"
	local mode="$2"
	local flags="${3:-}"
	local exe="$artifact_dir/quickjs-smoke-${name}.exe"
	local log="$artifact_dir/quickjs-smoke-${name}-build.log"

	printf '\nSTATIC_LINK_CANDIDATE=%s\n' "$name"
	case "$mode" in
		cgo-ldflags)
			if ! CGO_LDFLAGS="$flags" go build -x -tags quickjs -o "$exe" ./.github/scripts/quickjs-smoke >"$log" 2>&1; then
				printf 'STATIC_BUILD=FAIL (%s)\n' "$name"
				tail -n 60 "$log"
				return 1
			fi
			;;
		external-ldflags)
			if ! go build -x -tags quickjs -ldflags="$flags" -o "$exe" ./.github/scripts/quickjs-smoke >"$log" 2>&1; then
				printf 'STATIC_BUILD=FAIL (%s)\n' "$name"
				tail -n 60 "$log"
				return 1
			fi
			;;
		*)
			printf 'Unsupported static build mode: %s\n' "$mode" >&2
			return 1
			;;
	esac
	printf 'STATIC_BUILD=PASS (%s)\n' "$name"
	if ! inspect_pe "$exe" "$name" true; then
		printf 'STATIC_PE_CHECK=FAIL (%s)\n' "$name"
		return 1
	fi
	if ! "$exe"; then
		printf 'STATIC_NORMAL_PATH_SMOKE=FAIL (%s)\n' "$name"
		return 1
	fi
	if ! run_isolated "$exe"; then
		printf 'STATIC_ISOLATED_SMOKE=FAIL (%s)\n' "$name"
		return 1
	fi
	printf 'STATIC_LINK_STATUS=PASS (%s)\n' "$name" | tee "$artifact_dir/static-link-result.txt"
	return 0
}

build_baseline

if try_static_build cgo-winpthread cgo-ldflags '-Wl,-Bstatic -lwinpthread -Wl,-Bdynamic'; then
	exit 0
fi
if try_static_build cgo-pthread cgo-ldflags '-Wl,-Bstatic -lpthread -Wl,-Bdynamic'; then
	exit 0
fi
if try_static_build ext-winpthread external-ldflags '-linkmode external -extldflags "-Wl,-Bstatic -lwinpthread -Wl,-Bdynamic"'; then
	exit 0
fi
if try_static_build ext-pthread external-ldflags '-linkmode external -extldflags "-Wl,-Bstatic -lpthread -Wl,-Bdynamic"'; then
	exit 0
fi
if try_static_build whole-static external-ldflags '-linkmode external -extldflags "-static"'; then
	exit 0
fi

printf 'STATIC_LINK_STATUS=FAIL (all temporary link candidates failed)\n' | tee "$artifact_dir/static-link-result.txt"
exit 1
