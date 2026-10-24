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

declare -A binutils_path binutils_arg_mode

resolve_gcc_tool() {
	local name="$1"
	local lookup="$2"
	local resolved="$lookup"

	if [[ "$lookup" == "$name" || "$lookup" == "$name.exe" ]]; then
		resolved="$(command -v "$name" || command -v "$name.exe" || true)"
	fi
	if [[ -z "$resolved" ]]; then
		printf 'BINUTIL_%s_PATH=NOT_FOUND (GCC lookup: %s)\n' "$name" "$lookup" >&2
		return 1
	fi
	printf '%s\n' "$resolved"
}

tool_archive_argument_mode() {
	local lookup="$1"
	local tool_posix_path="$2"
	local tool_windows_path gcc_windows_path tool_dir gcc_dir gcc_target

	# GCC's drive-letter lookup is an explicit native-tool path. For PATH-based
	# lookups, use the toolchain directory/target or the MSYS usr/bin location;
	# fail closed for an unknown source rather than guessing a path convention.
	if [[ "$lookup" == [A-Za-z]:* ]]; then
		printf 'mingw-native\n'
		return
	fi
	tool_windows_path="$(cygpath -aw "$tool_posix_path" | tr '\\' '/' | tr '[:upper:]' '[:lower:]')"
	gcc_windows_path="$(cygpath -aw "$(command -v gcc)" | tr '\\' '/' | tr '[:upper:]' '[:lower:]')"
	tool_dir="${tool_windows_path%/*}"
	gcc_dir="${gcc_windows_path%/*}"
	gcc_target="$(gcc -dumpmachine)"
	if [[ "$tool_dir" == "$gcc_dir" && "$gcc_target" == *mingw* ]]; then
		printf 'mingw-native\n'
	elif [[ "$tool_posix_path" == /usr/bin/* || "$tool_posix_path" == */usr/bin/* ]]; then
		printf 'posix\n'
	else
		printf 'Cannot determine archive path convention for %s (GCC lookup: %s; resolved path: %s)\n' \
			"${tool_posix_path##*/}" "$lookup" "$tool_posix_path" >&2
		return 1
	fi
}

prepare_binutils() {
	local name="$1"
	local lookup resolved posix_path path_mode tool_type tool_version
	lookup="$(gcc -print-prog-name="$name" | tr -d '\r')"
	resolved="$(resolve_gcc_tool "$name" "$lookup")"
	posix_path="$(cygpath -u "$resolved" | tr -d '\r')"
	if [[ ! -x "$posix_path" ]]; then
		printf 'BINUTIL_%s_EXECUTABLE=NOT_EXECUTABLE (%s)\n' "$name" "$resolved" >&2
		return 1
	fi
	path_mode="$(tool_archive_argument_mode "$lookup" "$posix_path")"
	if ! tool_type="$(file -b "$posix_path")"; then
		printf 'BINUTIL_%s_FILE_TYPE=FAIL (%s)\n' "$name" "$resolved" >&2
		return 1
	fi
	if ! tool_version="$("$posix_path" --version 2>&1)"; then
		printf '%s\n' "$tool_version" >&2
		printf 'BINUTIL_%s_VERSION=FAIL (%s)\n' "$name" "$resolved" >&2
		return 1
	fi
	tool_version="${tool_version%%$'\n'*}"
	binutils_path["$name"]="$posix_path"
	binutils_arg_mode["$name"]="$path_mode"
	{
		printf 'BINUTIL_%s_GCC_LOOKUP=%s\n' "$name" "$lookup"
		printf 'BINUTIL_%s_PATH=%s\n' "$name" "$resolved"
		printf 'BINUTIL_%s_POSIX_PATH=%s\n' "$name" "$posix_path"
		printf 'BINUTIL_%s_ARCHIVE_ARGUMENT_MODE=%s\n' "$name" "$path_mode"
		printf 'BINUTIL_%s_FILE_TYPE=%s\n' "$name" "$tool_type"
		printf 'BINUTIL_%s_VERSION=%s\n' "$name" "$tool_version"
	} | tee -a "$artifact_dir/binutils-tools.log"
}

: > "$artifact_dir/binutils-tools.log"
for binutil in ar objdump nm dlltool; do
	prepare_binutils "$binutil"
done

archive_argument_for_tool() {
	local tool="$1"
	local raw_path="$2"
	local posix_path="$3"
	if [[ "${binutils_arg_mode[$tool]}" == "mingw-native" ]]; then
		if [[ "$raw_path" == [A-Za-z]:* ]]; then
			printf '%s\n' "$raw_path"
		else
			cygpath -aw "$posix_path" | tr -d '\r'
		fi
	else
		printf '%s\n' "$posix_path"
	fi
}

inspect_archive() {
	local name="$1"
	local expected_kind="$2"
	local required="${3:-optional}"
	local stem="${name//./-}"
	local raw_path archive_posix_path archive_type archive_sha256
	local tool_archive_path command_status dlltool_status
	local failed=0 nm_succeeded=0 pthread_symbols_found=0 import_symbols_found=0 import_sections_found=0
	local dlltool_succeeded=0 dll_import_target="" archive_kind="UNKNOWN"
	local members_file="$artifact_dir/${stem}-members.txt"
	local members_error="$artifact_dir/${stem}-members.stderr.log"
	local object_file="$artifact_dir/${stem}-objects.txt"
	local object_error="$artifact_dir/${stem}-objects.stderr.log"
	local defined_symbols_file="$artifact_dir/${stem}-defined-symbols.txt"
	local symbols_file="$artifact_dir/${stem}-pthread-symbols.txt"
	local import_symbols_file="$artifact_dir/${stem}-pthread-import-symbols.txt"
	local symbols_error="$artifact_dir/${stem}-pthread-symbols.stderr.log"
	local dll_id_file="$artifact_dir/${stem}-dlltool-identify.txt"
	local dll_id_error="$artifact_dir/${stem}-dlltool-identify.stderr.log"

	raw_path="$(gcc -print-file-name="$name" | tr -d '\r')"
	printf '\nARCHIVE_CANDIDATE %s\nGCC_LOOKUP=%s\nEXPECTED_KIND=%s\n' "$name" "$raw_path" "$expected_kind"
	if [[ "$raw_path" == "$name" ]]; then
		printf 'ARCHIVE_STATUS=NOT_FOUND\n'
		if [[ "$required" == "required" ]]; then
			printf 'ARCHIVE_MEMBERS=FAIL (required archive is missing)\n'
			printf 'PTHREAD_SYMBOL_CHECK=FAIL (archive is missing; check was not run)\n'
			printf 'ARCHIVE_INSPECTION=FAIL (required archive is missing)\n'
			return 1
		fi
		return 0
	fi
	archive_posix_path="$(cygpath -u "$raw_path" | tr -d '\r')"
	if [[ ! -f "$archive_posix_path" || ! -r "$archive_posix_path" ]]; then
		printf 'ARCHIVE_GCC_PATH=%s\nARCHIVE_POSIX_PATH=%s\n' "$raw_path" "$archive_posix_path"
		printf 'ARCHIVE_STATUS=FAIL (not a readable file)\n'
		printf 'ARCHIVE_MEMBERS=FAIL (archive is missing or unreadable)\n'
		printf 'PTHREAD_SYMBOL_CHECK=FAIL (archive is missing or unreadable; check was not run)\n'
		printf 'ARCHIVE_INSPECTION=FAIL\n'
		return 1
	fi
	printf 'ARCHIVE_GCC_PATH=%s\nARCHIVE_POSIX_PATH=%s\n' "$raw_path" "$archive_posix_path"
	if ! archive_type="$(file -b "$archive_posix_path")"; then
		printf 'ARCHIVE_FILE_TYPE=FAIL\n'
		printf 'ARCHIVE_MEMBERS=FAIL (archive type probe failed; archive checks were not run)\n'
		printf 'PTHREAD_SYMBOL_CHECK=FAIL (archive type probe failed; symbol check was not run)\n'
		printf 'ARCHIVE_INSPECTION=FAIL\n'
		return 1
	fi
	printf 'ARCHIVE_FILE_TYPE=%s\n' "$archive_type"
	if ! file "$archive_posix_path"; then
		printf 'ARCHIVE_FILE_TYPE=FAIL (file command could not read the archive)\n'
		failed=1
	fi
	if [[ "$archive_type" != *archive* ]]; then
		printf 'ARCHIVE_TYPE_CHECK=FAIL (file did not recognize an archive)\n'
		failed=1
	else
		printf 'ARCHIVE_TYPE_CHECK=PASS\n'
	fi
	if archive_sha256="$(sha256sum "$archive_posix_path" | awk '{print $1}')"; then
		printf 'ARCHIVE_SHA256=%s\n' "$archive_sha256"
	else
		printf 'ARCHIVE_SHA256=FAIL\n'
		failed=1
	fi

	tool_archive_path="$(archive_argument_for_tool ar "$raw_path" "$archive_posix_path")"
	printf 'AR_ARCHIVE_ARGUMENT_MODE=%s\nAR_ARCHIVE_ARGUMENT=%s\n' "${binutils_arg_mode[ar]}" "$tool_archive_path"
	if "${binutils_path[ar]}" t "$tool_archive_path" >"$members_file" 2>"$members_error"; then
		if [[ -s "$members_file" ]]; then
			printf 'ARCHIVE_MEMBERS=PASS count=%s file=%s\n' "$(awk 'END { print NR }' "$members_file")" "$members_file"
		else
			printf 'ARCHIVE_MEMBERS=FAIL (ar succeeded but returned no members)\n'
			failed=1
		fi
		if [[ -s "$members_error" ]]; then cat "$members_error" >&2; fi
	else
		command_status=$?
		printf 'ARCHIVE_MEMBERS=FAIL (ar exit=%s)\n' "$command_status"
		cat "$members_error" >&2
		failed=1
	fi

	tool_archive_path="$(archive_argument_for_tool objdump "$raw_path" "$archive_posix_path")"
	printf 'OBJDUMP_ARCHIVE_ARGUMENT_MODE=%s\nOBJDUMP_ARCHIVE_ARGUMENT=%s\n' "${binutils_arg_mode[objdump]}" "$tool_archive_path"
	if "${binutils_path[objdump]}" -f -h "$tool_archive_path" >"$object_file" 2>"$object_error"; then
		if [[ -s "$object_file" ]]; then
			printf 'ARCHIVE_OBJECT_HEADERS=PASS file=%s\n' "$object_file"
			if grep -Eiq '\.idata\$' "$object_file"; then
				import_sections_found=1
				printf 'DLL_IMPORT_SECTION_MARKER=FOUND\n'
			else
				printf 'DLL_IMPORT_SECTION_MARKER=NOT_FOUND\n'
			fi
		else
			printf 'ARCHIVE_OBJECT_HEADERS=FAIL (objdump succeeded but returned no headers)\n'
			failed=1
		fi
		if [[ -s "$object_error" ]]; then cat "$object_error" >&2; fi
	else
		command_status=$?
		printf 'ARCHIVE_OBJECT_HEADERS=FAIL (objdump exit=%s)\n' "$command_status"
		cat "$object_error" >&2
		failed=1
	fi

	tool_archive_path="$(archive_argument_for_tool nm "$raw_path" "$archive_posix_path")"
	printf 'NM_ARCHIVE_ARGUMENT_MODE=%s\nNM_ARCHIVE_ARGUMENT=%s\n' "${binutils_arg_mode[nm]}" "$tool_archive_path"
	if "${binutils_path[nm]}" -A --defined-only "$tool_archive_path" >"$defined_symbols_file" 2>"$symbols_error"; then
		nm_succeeded=1
		if grep -E 'pthread_(mutex_lock|cond_wait|cond_timedwait)' "$defined_symbols_file" >"$symbols_file"; then
			pthread_symbols_found=1
			printf 'PTHREAD_SYMBOLS_FOUND=yes file=%s\n' "$symbols_file"
		else
			printf 'PTHREAD_SYMBOLS_FOUND=no (nm completed successfully; no matching definitions)\n'
		fi
		if grep -E '(__imp_|_imp__).*pthread_(mutex_lock|cond_wait|cond_timedwait)' "$defined_symbols_file" >"$import_symbols_file"; then
			import_symbols_found=1
			printf 'PTHREAD_IMPORT_SYMBOLS_FOUND=yes file=%s\n' "$import_symbols_file"
		else
			printf 'PTHREAD_IMPORT_SYMBOLS_FOUND=no (nm completed successfully)\n'
		fi
		if [[ -s "$symbols_error" ]]; then cat "$symbols_error" >&2; fi
	else
		command_status=$?
		printf 'PTHREAD_SYMBOL_CHECK=FAIL (nm exit=%s; symbol absence was not established)\n' "$command_status"
		cat "$symbols_error" >&2
		failed=1
	fi

	tool_archive_path="$(archive_argument_for_tool dlltool "$raw_path" "$archive_posix_path")"
	printf 'DLLTOOL_ARCHIVE_ARGUMENT_MODE=%s\nDLLTOOL_ARCHIVE_ARGUMENT=%s\n' "${binutils_arg_mode[dlltool]}" "$tool_archive_path"
	if "${binutils_path[dlltool]}" -I "$tool_archive_path" >"$dll_id_file" 2>"$dll_id_error"; then
		dlltool_succeeded=1
		dll_import_target="$(tr -d '\r\n' <"$dll_id_file")"
		if [[ -n "$dll_import_target" ]]; then
			printf 'DLLTOOL_IDENTIFIED_IMPORT_TARGET=%s\n' "$dll_import_target"
		else
			printf 'DLLTOOL_IDENTIFICATION=FAIL (empty import target)\n'
			failed=1
		fi
		if [[ -s "$dll_id_error" ]]; then cat "$dll_id_error" >&2; fi
	else
		dlltool_status=$?
		printf 'DLLTOOL_IMPORT_PROBE=NOT_IDENTIFIED (dlltool exit=%s)\n' "$dlltool_status"
		cat "$dll_id_error" >&2
	fi
	if [[ "$dlltool_succeeded" == "1" && -n "$dll_import_target" ]]; then
		archive_kind="dll-import"
	elif [[ "$import_sections_found" == "1" || "$import_symbols_found" == "1" ]]; then
		archive_kind="dll-import"
		printf 'DLL_IMPORT_KIND=indicated by archive sections or defined import symbols\n'
	elif [[ "$nm_succeeded" == "1" && "$pthread_symbols_found" == "1" ]]; then
		archive_kind="static-implementation"
		printf 'DLL_IMPORT_CHECK=PASS (no import markers; pthread implementation definitions found)\n'
	fi

	printf 'ARCHIVE_KIND=%s\n' "$archive_kind"
	if [[ "$expected_kind" == "classify" && ( "$archive_kind" == "static-implementation" || "$archive_kind" == "dll-import" ) ]]; then
		printf 'ARCHIVE_KIND_CHECK=PASS (classified as %s)\n' "$archive_kind"
	elif [[ "$archive_kind" != "$expected_kind" ]]; then
		printf 'ARCHIVE_KIND_CHECK=FAIL (expected %s)\n' "$expected_kind"
		failed=1
	else
		printf 'ARCHIVE_KIND_CHECK=PASS\n'
	fi
	if [[ "$archive_kind" == "static-implementation" ]]; then
		if [[ "$pthread_symbols_found" != "1" || "$import_symbols_found" == "1" || "$import_sections_found" == "1" || "$dlltool_succeeded" == "1" ]]; then
			printf 'STATIC_PTHREAD_SYMBOL_CHECK=FAIL (implementation symbols missing or import-library markers present)\n'
			failed=1
		else
			printf 'STATIC_PTHREAD_SYMBOL_CHECK=PASS\n'
		fi
	elif [[ "$archive_kind" == "dll-import" && ( "$dlltool_succeeded" != "1" || -z "$dll_import_target" ) ]]; then
		printf 'DLL_IMPORT_CHECK=FAIL (dlltool did not identify an import target)\n'
		failed=1
	fi
	if [[ "$failed" != "0" ]]; then
		printf 'ARCHIVE_INSPECTION=FAIL\n'
		return 1
	fi
	printf 'ARCHIVE_INSPECTION=PASS\n'
}

archive_inspection_failed=0
if ! inspect_archive libwinpthread.a static-implementation required; then
	archive_inspection_failed=1
fi
if ! inspect_archive libpthread.a classify; then
	archive_inspection_failed=1
fi
if ! inspect_archive libwinpthread.dll.a dll-import; then
	archive_inspection_failed=1
fi
if [[ "$archive_inspection_failed" == "0" ]]; then
	printf '\nARCHIVE_INSPECTION_STATUS=PASS\n'
else
	printf '\nARCHIVE_INSPECTION_STATUS=FAIL\n'
fi

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

accept_static_candidate() {
	if [[ "$archive_inspection_failed" != "0" ]]; then
		printf 'STATIC_LINK_ACCEPTANCE=FAIL (archive inspection failed despite successful Smoke link)\n'
		return 1
	fi
	printf 'STATIC_LINK_ACCEPTANCE=PASS (archive inspection passed)\n'
}

build_baseline

if try_static_build cgo-winpthread cgo-ldflags '-Wl,-Bstatic -lwinpthread -Wl,-Bdynamic'; then
	if accept_static_candidate; then exit 0; else exit 1; fi
fi
if try_static_build cgo-pthread cgo-ldflags '-Wl,-Bstatic -lpthread -Wl,-Bdynamic'; then
	if accept_static_candidate; then exit 0; else exit 1; fi
fi
if try_static_build ext-winpthread external-ldflags '-linkmode external -extldflags "-Wl,-Bstatic -lwinpthread -Wl,-Bdynamic"'; then
	if accept_static_candidate; then exit 0; else exit 1; fi
fi
if try_static_build ext-pthread external-ldflags '-linkmode external -extldflags "-Wl,-Bstatic -lpthread -Wl,-Bdynamic"'; then
	if accept_static_candidate; then exit 0; else exit 1; fi
fi
if try_static_build whole-static external-ldflags '-linkmode external -extldflags "-static"'; then
	if accept_static_candidate; then exit 0; else exit 1; fi
fi

printf 'STATIC_LINK_STATUS=FAIL (all temporary link candidates failed)\n' | tee "$artifact_dir/static-link-result.txt"
exit 1
