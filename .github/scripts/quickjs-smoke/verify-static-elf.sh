#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -lt 1 ]]; then
	printf 'usage: %s <elf> [<elf> ...]\n' "$0" >&2
	exit 2
fi

for binary in "$@"; do
	[[ -s "$binary" ]] || { printf 'missing or empty ELF: %s\n' "$binary" >&2; exit 1; }
	printf '\nSTATIC_ELF_CHECK %s\n' "$binary"
	file "$binary"
	readelf -h "$binary" | grep -E 'Class:|Type:|Machine:'
	if readelf -h "$binary" | grep -Fq 'Advanced Micro Devices X86-64'; then
		:
	else
		printf 'ELF_MACHINE_CHECK=FAIL (expected amd64)\n' >&2
		exit 1
	fi
	if readelf -lW "$binary" | grep -Eq '^[[:space:]]*INTERP([[:space:]]|$)'; then
		printf 'ELF_INTERPRETER_CHECK=FAIL\n' >&2
		readelf -lW "$binary" | grep -A1 -B1 INTERP >&2 || true
		exit 1
	fi
	printf 'ELF_INTERPRETER_CHECK=PASS (no PT_INTERP)\n'

	dynamic_info="$(readelf -dW "$binary" 2>&1)"
	if grep -Fq 'Dynamic section at' <<<"$dynamic_info"; then
		printf '%s\n' "$dynamic_info" >&2
		printf 'ELF_DYNAMIC_SECTION_CHECK=FAIL\n' >&2
		exit 1
	fi
	if grep -Fq '(NEEDED)' <<<"$dynamic_info"; then
		printf '%s\n' "$dynamic_info" >&2
		printf 'ELF_DT_NEEDED_CHECK=FAIL\n' >&2
		exit 1
	fi
	if ! grep -Fq 'There is no dynamic section' <<<"$dynamic_info"; then
		printf '%s\n' "$dynamic_info" >&2
		printf 'ELF_DYNAMIC_SECTION_CHECK=UNRECOGNIZED\n' >&2
		exit 1
	fi
	if ! file "$binary" | grep -Fq 'statically linked'; then
		printf 'FILE_STATIC_CHECK=FAIL\n' >&2
		exit 1
	fi
	printf 'ELF_DYNAMIC_SECTION_CHECK=PASS (no dynamic section, no DT_NEEDED)\n'
	printf 'ELF_STATIC_CHECK=PASS\n'
done
