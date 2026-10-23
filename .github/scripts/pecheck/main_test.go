package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"debug/pe"
)

func TestRejectsNonPEFile(t *testing.T) {
	assertRunFails(t, []byte("this is not a PE file"), "PE Header invalid")
}

func TestRejectsWrongPEArchitecture(t *testing.T) {
	assertRunFails(t, makeFixture(t, pe.IMAGE_FILE_MACHINE_I386, false, directory{}), "PE architecture mismatch")
}

func TestRejectsNonzeroUnmappableImportDirectory(t *testing.T) {
	assertRunFails(t, makeFixture(t, pe.IMAGE_FILE_MACHINE_AMD64, true, directory{rva: 0x1800, size: 20}), "outside every section")
}

func TestRejectsImportDirectoryWithOnlyOneNonzeroField(t *testing.T) {
	assertRunFails(t, makeFixture(t, pe.IMAGE_FILE_MACHINE_AMD64, true, directory{rva: 0x1000}), "both be zero or both be nonzero")
}

func TestRejectsMalformedNonzeroImportDirectory(t *testing.T) {
	image := makeFixture(t, pe.IMAGE_FILE_MACHINE_AMD64, true, directory{rva: 0x1000, size: 40})
	raw := image[0x200:]
	binary.LittleEndian.PutUint32(raw[0:4], 0x1040)
	binary.LittleEndian.PutUint32(raw[16:20], 0x1050)
	assertRunFails(t, image, "zero Name")
}

func TestAcceptsValidEmptyImportDirectory(t *testing.T) {
	image := makeFixture(t, pe.IMAGE_FILE_MACHINE_AMD64, true, directory{rva: 0x1000, size: 20})
	direct, delay := runFixture(t, image)
	for _, path := range []string{direct, delay} {
		content, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if len(content) != 0 {
			t.Fatalf("expected empty import list in %s, got %q", path, content)
		}
	}
}

func TestAcceptsValidNonemptyImportDirectory(t *testing.T) {
	image := makeFixture(t, pe.IMAGE_FILE_MACHINE_AMD64, true, directory{rva: 0x1000, size: 40})
	raw := image[0x200:]
	binary.LittleEndian.PutUint32(raw[0:4], 0x1040) // OriginalFirstThunk.
	binary.LittleEndian.PutUint32(raw[12:16], 0x1028)
	binary.LittleEndian.PutUint32(raw[16:20], 0x1050) // FirstThunk.
	copy(raw[40:], []byte("kernel32.dll\x00"))
	binary.LittleEndian.PutUint64(raw[64:72], 0x1080)
	binary.LittleEndian.PutUint64(raw[80:88], 0x1080)
	binary.LittleEndian.PutUint16(raw[128:130], 0)
	copy(raw[130:], []byte("ExitProcess\x00"))
	direct, _ := runFixture(t, image)
	content, err := os.ReadFile(direct)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "kernel32.dll\n" {
		t.Fatalf("unexpected direct import list %q", content)
	}
}

func TestParsesValidDelayImportDirectory(t *testing.T) {
	image := makeFixtureWithDirectories(t, pe.IMAGE_FILE_MACHINE_AMD64, true, directory{}, directory{rva: 0x1000, size: 64})
	raw := image[0x200:]
	binary.LittleEndian.PutUint32(raw[0:4], 1)        // RVA-based delay import descriptor.
	binary.LittleEndian.PutUint32(raw[4:8], 0x1068)   // DLL Name.
	binary.LittleEndian.PutUint32(raw[12:16], 0x1078) // IAT.
	binary.LittleEndian.PutUint32(raw[16:20], 0x1048) // Import Name Table.
	copy(raw[104:], []byte("delay.dll\x00"))
	binary.LittleEndian.PutUint64(raw[72:80], 0x1090)
	binary.LittleEndian.PutUint64(raw[120:128], 0x1090)
	binary.LittleEndian.PutUint16(raw[144:146], 0)
	copy(raw[146:], []byte("DelayedCall\x00"))
	_, delay := runFixture(t, image)
	content, err := os.ReadFile(delay)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "delay.dll\n" {
		t.Fatalf("unexpected delay import list %q", content)
	}
}

func TestRejectsImportDirectoryWithoutDescriptorTerminator(t *testing.T) {
	image := makeFixture(t, pe.IMAGE_FILE_MACHINE_AMD64, true, directory{rva: 0x1000, size: 20})
	raw := image[0x200:]
	binary.LittleEndian.PutUint32(raw[0:4], 0x1040)
	binary.LittleEndian.PutUint32(raw[12:16], 0x1028)
	binary.LittleEndian.PutUint32(raw[16:20], 0x1050)
	copy(raw[40:], []byte("kernel32.dll\x00"))
	binary.LittleEndian.PutUint64(raw[64:72], 0x1080)
	binary.LittleEndian.PutUint64(raw[80:88], 0x1080)
	binary.LittleEndian.PutUint16(raw[128:130], 0)
	copy(raw[130:], []byte("ExitProcess\x00"))
	assertRunFails(t, image, "descriptor terminator not found")
}

func assertRunFails(t *testing.T, image []byte, expected string) {
	t.Helper()
	path := writeFixture(t, image)
	direct := filepath.Join(t.TempDir(), "direct.txt")
	delay := filepath.Join(t.TempDir(), "delay.txt")
	err := run(path, direct, delay)
	if err == nil || !strings.Contains(err.Error(), expected) {
		t.Fatalf("run() error = %v, want error containing %q", err, expected)
	}
}

func runFixture(t *testing.T, image []byte) (string, string) {
	t.Helper()
	path := writeFixture(t, image)
	directory := t.TempDir()
	direct := filepath.Join(directory, "direct.txt")
	delay := filepath.Join(directory, "delay.txt")
	if err := run(path, direct, delay); err != nil {
		t.Fatalf("run() failed for valid fixture: %v", err)
	}
	return direct, delay
}

func writeFixture(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fixture.exe")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func makeFixture(t *testing.T, machine uint16, pe32Plus bool, importDir directory) []byte {
	t.Helper()
	return makeFixtureWithDirectories(t, machine, pe32Plus, importDir, directory{})
}

func makeFixtureWithDirectories(t *testing.T, machine uint16, pe32Plus bool, importDir, delayDir directory) []byte {
	t.Helper()
	const (
		ntOffset  = 0x80
		rawOffset = 0x200
		rawSize   = 0x200
	)
	file := make([]byte, rawOffset+rawSize)
	copy(file[:2], "MZ")
	binary.LittleEndian.PutUint32(file[0x3c:0x40], ntOffset)
	copy(file[ntOffset:ntOffset+4], []byte{'P', 'E', 0, 0})
	coffOffset := ntOffset + 4
	binary.LittleEndian.PutUint16(file[coffOffset:coffOffset+2], machine)
	binary.LittleEndian.PutUint16(file[coffOffset+2:coffOffset+4], 1)
	optionalSize := uint16(240)
	if !pe32Plus {
		optionalSize = 224
	}
	binary.LittleEndian.PutUint16(file[coffOffset+16:coffOffset+18], optionalSize)
	binary.LittleEndian.PutUint16(file[coffOffset+18:coffOffset+20], 0x0002)

	optionalOffset := coffOffset + 20
	if pe32Plus {
		optional := pe.OptionalHeader64{
			Magic:               0x20b,
			ImageBase:           0x140000000,
			SectionAlignment:    0x1000,
			FileAlignment:       0x200,
			SizeOfImage:         0x2000,
			SizeOfHeaders:       rawOffset,
			Subsystem:           pe.IMAGE_SUBSYSTEM_WINDOWS_CUI,
			NumberOfRvaAndSizes: 16,
			DataDirectory:       [16]pe.DataDirectory{},
		}
		optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT] = pe.DataDirectory{VirtualAddress: importDir.rva, Size: importDir.size}
		optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] = pe.DataDirectory{VirtualAddress: delayDir.rva, Size: delayDir.size}
		encoded := new(bytes.Buffer)
		if err := binary.Write(encoded, binary.LittleEndian, optional); err != nil {
			t.Fatal(err)
		}
		copy(file[optionalOffset:], encoded.Bytes())
	} else {
		optional := pe.OptionalHeader32{
			Magic:               0x10b,
			ImageBase:           0x400000,
			SectionAlignment:    0x1000,
			FileAlignment:       0x200,
			SizeOfImage:         0x2000,
			SizeOfHeaders:       rawOffset,
			Subsystem:           pe.IMAGE_SUBSYSTEM_WINDOWS_CUI,
			NumberOfRvaAndSizes: 16,
			DataDirectory:       [16]pe.DataDirectory{},
		}
		optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT] = pe.DataDirectory{VirtualAddress: importDir.rva, Size: importDir.size}
		optional.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT] = pe.DataDirectory{VirtualAddress: delayDir.rva, Size: delayDir.size}
		encoded := new(bytes.Buffer)
		if err := binary.Write(encoded, binary.LittleEndian, optional); err != nil {
			t.Fatal(err)
		}
		copy(file[optionalOffset:], encoded.Bytes())
	}

	sectionOffset := optionalOffset + int(optionalSize)
	var section pe.SectionHeader32
	copy(section.Name[:], ".idata")
	section.VirtualSize = rawSize
	section.VirtualAddress = 0x1000
	section.SizeOfRawData = rawSize
	section.PointerToRawData = rawOffset
	section.Characteristics = 0xc0000040
	encodedSection := new(bytes.Buffer)
	if err := binary.Write(encodedSection, binary.LittleEndian, section); err != nil {
		t.Fatal(err)
	}
	copy(file[sectionOffset:], encodedSection.Bytes())
	return file
}
