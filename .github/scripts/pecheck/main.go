// Command pecheck validates PE32+ x64 import directories for the M6.1 CI job.
// It uses debug/pe for the independent header/section parse, then bounds-checks
// directory RVAs, descriptors, names, and thunk tables against the file bytes.
package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

const (
	maxDirectorySize = 16 << 20
	maxStringSize    = 4096
	maxThunkEntries  = 1 << 20
	imageScnMemRead  = 0x40000000
)

type directory struct {
	rva  uint32
	size uint32
}

type sectionRange struct {
	section  *pe.Section
	start    uint64
	end      uint64
	rawStart uint64
	rawEnd   uint64
}

type image struct {
	file      *os.File
	pe        *pe.File
	fileSize  int64
	optional  *pe.OptionalHeader64
	sections  []sectionRange
	imageBase uint64
}

type importResult struct {
	section     string
	fileOff     int64
	libraries   []string
	descriptors []importDescriptor
}

type importDescriptor struct {
	index     int
	nameRVA   uint32
	lookupRVA uint32
	thunkRVA  uint32
	name      string
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: pecheck <pe-file> <direct-imports.txt> <delay-imports.txt>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Args[3]); err != nil {
		fmt.Fprintf(os.Stderr, "PE validation failed: %v\n", err)
		os.Exit(1)
	}
}

func run(path, directOut, delayOut string) error {
	img, err := openImage(path)
	if err != nil {
		return err
	}
	defer img.close()

	fmt.Printf("PE file: %s\n", path)
	fmt.Printf("Parser: Go debug/pe plus bounded raw RVA validation\n")
	fmt.Printf("Machine: 0x%04x\n", img.pe.Machine)
	fmt.Printf("Optional Header: PE32+ magic=0x%04x NumberOfRvaAndSizes=%d ImageBase=0x%x SizeOfImage=0x%x SizeOfHeaders=0x%x\n",
		img.optional.Magic, img.optional.NumberOfRvaAndSizes, img.imageBase, img.optional.SizeOfImage, img.optional.SizeOfHeaders)
	fmt.Printf("Section Table: %d sections\n", len(img.pe.Sections))
	for _, section := range img.pe.Sections {
		fmt.Printf("  %q RVA=0x%08x VirtualSize=0x%08x RawSize=0x%08x RawOffset=0x%08x Characteristics=0x%08x\n",
			section.Name, section.VirtualAddress, section.VirtualSize, section.Size, section.Offset, section.Characteristics)
	}

	directDir, err := img.dataDirectory(pe.IMAGE_DIRECTORY_ENTRY_IMPORT)
	if err != nil {
		return fmt.Errorf("Import Directory header: %w", err)
	}
	direct, err := img.parseImportDirectory(directDir, false)
	if err != nil {
		return fmt.Errorf("Import Directory RVA=0x%08x Size=0x%x: %w", directDir.rva, directDir.size, err)
	}
	fmt.Printf("Import Directory: RVA=0x%08x Size=0x%x", directDir.rva, directDir.size)
	if directDir.rva == 0 && directDir.size == 0 {
		fmt.Printf(" (absent)\n")
	} else {
		fmt.Printf(" Section=%q FileOffset=0x%x\n", direct.section, direct.fileOff)
	}
	printDescriptors("Import", direct.descriptors)
	if len(direct.libraries) == 0 {
		fmt.Printf("Direct import result: VALID_EMPTY_IMPORT_DIRECTORY\n")
	} else {
		fmt.Printf("Direct import result: VALID_NONEMPTY_IMPORT_DIRECTORY (%d DLLs)\n", len(direct.libraries))
	}
	if err := crossCheckDebugPEImports(img, direct.libraries); err != nil {
		return err
	}
	if err := writeNames(directOut, direct.libraries); err != nil {
		return fmt.Errorf("write direct import list: %w", err)
	}

	delayDir, err := img.dataDirectory(pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
	if err != nil {
		return fmt.Errorf("Delay Import Directory header: %w", err)
	}
	delay, err := img.parseImportDirectory(delayDir, true)
	if err != nil {
		return fmt.Errorf("Delay Import Directory RVA=0x%08x Size=0x%x: %w", delayDir.rva, delayDir.size, err)
	}
	fmt.Printf("Delay Import Directory: RVA=0x%08x Size=0x%x", delayDir.rva, delayDir.size)
	if delayDir.rva == 0 && delayDir.size == 0 {
		fmt.Printf(" (absent)\n")
	} else {
		fmt.Printf(" Section=%q FileOffset=0x%x\n", delay.section, delay.fileOff)
	}
	printDescriptors("Delay Import", delay.descriptors)
	if len(delay.libraries) == 0 {
		fmt.Printf("Delay import result: VALID_EMPTY_DELAY_IMPORT_DIRECTORY\n")
	} else {
		fmt.Printf("Delay import result: VALID_NONEMPTY_DELAY_IMPORT_DIRECTORY (%d DLLs)\n", len(delay.libraries))
	}
	for _, name := range direct.libraries {
		fmt.Printf("Direct DLL Name: %s\n", name)
	}
	for _, name := range delay.libraries {
		fmt.Printf("Delay DLL Name: %s\n", name)
	}
	if err := writeNames(delayOut, delay.libraries); err != nil {
		return fmt.Errorf("write delay import list: %w", err)
	}
	fmt.Printf("PE_IMPORT_VALIDATION=PASS\n")
	return nil
}

func openImage(path string) (*image, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open PE file: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat PE file: %w", err)
	}
	if info.Size() < 64 {
		file.Close()
		return nil, fmt.Errorf("PE Header invalid: file is too small (%d bytes)", info.Size())
	}
	var dos [64]byte
	if _, err := file.ReadAt(dos[:], 0); err != nil {
		file.Close()
		return nil, fmt.Errorf("PE Header invalid: read DOS header: %w", err)
	}
	if !bytes.Equal(dos[:2], []byte("MZ")) {
		file.Close()
		return nil, errors.New("PE Header invalid: missing MZ signature")
	}
	peOffset := uint64(binary.LittleEndian.Uint32(dos[0x3c:0x40]))
	if peOffset > uint64(info.Size()) || uint64(info.Size())-peOffset < 24 {
		file.Close()
		return nil, errors.New("PE Header invalid: e_lfanew is outside the file")
	}
	var signatureAndHeader [24]byte
	if _, err := file.ReadAt(signatureAndHeader[:], int64(peOffset)); err != nil {
		file.Close()
		return nil, fmt.Errorf("PE Header invalid: read COFF header: %w", err)
	}
	if !bytes.Equal(signatureAndHeader[:4], []byte{'P', 'E', 0, 0}) {
		file.Close()
		return nil, errors.New("PE Header invalid: missing PE signature")
	}
	coff := signatureAndHeader[4:]
	numSections := binary.LittleEndian.Uint16(coff[2:4])
	optionalSize := binary.LittleEndian.Uint16(coff[16:18])
	if numSections == 0 {
		file.Close()
		return nil, errors.New("PE Section Table invalid: contains no sections")
	}
	sectionTable := peOffset + 24 + uint64(optionalSize)
	sectionTableEnd := sectionTable + uint64(numSections)*40
	if sectionTableEnd < sectionTable || sectionTableEnd > uint64(info.Size()) {
		file.Close()
		return nil, errors.New("PE Section Table invalid: table exceeds file bounds")
	}

	parsed, err := parseDebugPE(file)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("PE Header/Section Table parse failure (debug/pe): %w", err)
	}
	if parsed.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		parsed.Close()
		file.Close()
		return nil, fmt.Errorf("PE architecture mismatch: expected AMD64 (0x8664), got 0x%04x", parsed.Machine)
	}
	optional, ok := parsed.OptionalHeader.(*pe.OptionalHeader64)
	if !ok || optional.Magic != 0x20b {
		parsed.Close()
		file.Close()
		return nil, errors.New("PE architecture mismatch: expected PE32+ Optional Header")
	}
	if int(parsed.NumberOfSections) != len(parsed.Sections) || int(parsed.NumberOfSections) != int(numSections) {
		parsed.Close()
		file.Close()
		return nil, errors.New("PE Section Table invalid: parsed section count differs from COFF header")
	}
	if uint64(optional.SizeOfHeaders) < sectionTableEnd || uint64(optional.SizeOfHeaders) > uint64(info.Size()) {
		parsed.Close()
		file.Close()
		return nil, fmt.Errorf("PE Header invalid: SizeOfHeaders 0x%x does not contain the headers and section table", optional.SizeOfHeaders)
	}
	if optional.NumberOfRvaAndSizes > uint32(len(optional.DataDirectory)) {
		parsed.Close()
		file.Close()
		return nil, fmt.Errorf("PE Optional Header invalid: unsupported NumberOfRvaAndSizes=%d", optional.NumberOfRvaAndSizes)
	}

	img := &image{file: file, pe: parsed, fileSize: info.Size(), optional: optional, imageBase: optional.ImageBase}
	for _, section := range parsed.Sections {
		rawStart := uint64(section.Offset)
		rawEnd := rawStart + uint64(section.Size)
		if rawEnd < rawStart || rawEnd > uint64(info.Size()) || (section.Size > 0 && rawStart < uint64(optional.SizeOfHeaders)) {
			img.close()
			return nil, fmt.Errorf("PE Section Table invalid: section %q raw range [0x%x,0x%x) overlaps headers or exceeds file size 0x%x", section.Name, rawStart, rawEnd, info.Size())
		}
		if section.Size > 0 {
			for _, previous := range img.sections {
				if rawStart < previous.rawEnd && previous.rawStart < rawEnd {
					img.close()
					return nil, fmt.Errorf("PE Section Table invalid: raw ranges for %q and %q overlap", previous.section.Name, section.Name)
				}
			}
		}
		virtualSize := uint64(section.VirtualSize)
		if virtualSize < uint64(section.Size) {
			virtualSize = uint64(section.Size)
		}
		start := uint64(section.VirtualAddress)
		end := start + virtualSize
		if end < start || end > 1<<32 {
			img.close()
			return nil, fmt.Errorf("PE Section Table invalid: section %q virtual range overflows RVA space", section.Name)
		}
		if virtualSize > 0 {
			for _, previous := range img.sections {
				if start < previous.end && previous.start < end {
					img.close()
					return nil, fmt.Errorf("PE Section Table invalid: virtual ranges for %q and %q overlap", previous.section.Name, section.Name)
				}
			}
			img.sections = append(img.sections, sectionRange{section: section, start: start, end: end, rawStart: rawStart, rawEnd: rawEnd})
		}
	}
	return img, nil
}

func parseDebugPE(file *os.File) (parsed *pe.File, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("debug/pe parser execution failure (panic): %v", recovered)
		}
	}()
	return pe.NewFile(file)
}

func (img *image) close() {
	if img.pe != nil {
		_ = img.pe.Close()
		img.pe = nil
	}
	if img.file != nil {
		_ = img.file.Close()
		img.file = nil
	}
}

func (img *image) dataDirectory(index int) (directory, error) {
	if img.optional.NumberOfRvaAndSizes <= uint32(index) {
		return directory{}, nil
	}
	entry := img.optional.DataDirectory[index]
	return directory{rva: entry.VirtualAddress, size: entry.Size}, nil
}

func (img *image) parseImportDirectory(dir directory, delay bool) (importResult, error) {
	result := importResult{}
	if dir.rva == 0 && dir.size == 0 {
		return result, nil
	}
	if dir.rva == 0 || dir.size == 0 {
		return result, errors.New("RVA and Size must either both be zero or both be nonzero")
	}
	if uint64(dir.rva)+uint64(dir.size) > uint64(img.optional.SizeOfImage) {
		return result, fmt.Errorf("directory RVA range exceeds SizeOfImage 0x%x", img.optional.SizeOfImage)
	}
	if dir.size > maxDirectorySize {
		return result, fmt.Errorf("directory size 0x%x exceeds validation limit 0x%x", dir.size, maxDirectorySize)
	}
	descriptorSize := uint32(20)
	if delay {
		descriptorSize = 32
	}
	if dir.size < descriptorSize {
		return result, fmt.Errorf("directory size 0x%x cannot contain a descriptor and terminator", dir.size)
	}
	data, section, fileOffset, err := img.readRVA(dir.rva, dir.size)
	if err != nil {
		return result, fmt.Errorf("directory RVA range does not map to file bytes: %w", err)
	}
	if section.Characteristics&imageScnMemRead == 0 {
		return result, fmt.Errorf("directory is in non-readable section %q", section.Name)
	}
	result.section = section.Name
	result.fileOff = fileOffset
	terminated := false
	for offset := uint32(0); offset+descriptorSize <= dir.size; offset += descriptorSize {
		record := data[offset : offset+descriptorSize]
		if allZero(record) {
			terminated = true
			break
		}
		var nameRVA uint32
		var thunkRVA uint32
		var lookupRVA uint32
		if delay {
			attrs := binary.LittleEndian.Uint32(record[0:4])
			nameField := binary.LittleEndian.Uint32(record[4:8])
			intField := binary.LittleEndian.Uint32(record[16:20])
			iatField := binary.LittleEndian.Uint32(record[12:16])
			if attrs&^uint32(1) != 0 {
				return result, fmt.Errorf("delay descriptor at +0x%x has unsupported attributes 0x%x", offset, attrs)
			}
			nameRVA, err = img.delayFieldRVA(nameField, attrs&1 != 0)
			if err != nil {
				return result, fmt.Errorf("delay descriptor at +0x%x Name: %w", offset, err)
			}
			lookupRVA, err = img.delayFieldRVA(intField, attrs&1 != 0)
			if err != nil {
				return result, fmt.Errorf("delay descriptor at +0x%x Import Name Table: %w", offset, err)
			}
			thunkRVA, err = img.delayFieldRVA(iatField, attrs&1 != 0)
			if err != nil {
				return result, fmt.Errorf("delay descriptor at +0x%x Import Address Table: %w", offset, err)
			}
		} else {
			originalThunk := binary.LittleEndian.Uint32(record[0:4])
			nameRVA = binary.LittleEndian.Uint32(record[12:16])
			thunkRVA = binary.LittleEndian.Uint32(record[16:20])
			lookupRVA = originalThunk
			if lookupRVA == 0 {
				lookupRVA = thunkRVA
			}
		}
		if nameRVA == 0 || thunkRVA == 0 || lookupRVA == 0 {
			return result, fmt.Errorf("descriptor at +0x%x has a zero Name, Import Name Table, or Import Address Table RVA", offset)
		}
		name, err := img.readCString(nameRVA, maxStringSize)
		if err != nil {
			return result, fmt.Errorf("descriptor at +0x%x DLL Name RVA 0x%08x: %w", offset, nameRVA, err)
		}
		if !validModuleName(name) {
			return result, fmt.Errorf("descriptor at +0x%x contains invalid DLL Name %q", offset, name)
		}
		if err := img.validateThunks(lookupRVA); err != nil {
			return result, fmt.Errorf("descriptor at +0x%x thunk table RVA 0x%08x: %w", offset, lookupRVA, err)
		}
		if err := img.validateThunkTerminator(thunkRVA); err != nil {
			return result, fmt.Errorf("descriptor at +0x%x IAT RVA 0x%08x: %w", offset, thunkRVA, err)
		}
		result.libraries = append(result.libraries, name)
		result.descriptors = append(result.descriptors, importDescriptor{
			index:     len(result.descriptors),
			nameRVA:   nameRVA,
			lookupRVA: lookupRVA,
			thunkRVA:  thunkRVA,
			name:      name,
		})
	}
	if !terminated {
		return result, fmt.Errorf("descriptor terminator not found within the declared directory size 0x%x", dir.size)
	}
	result.libraries = uniqueSorted(result.libraries)
	return result, nil
}

func (img *image) delayFieldRVA(value uint32, isRVA bool) (uint32, error) {
	if value == 0 || isRVA {
		return value, nil
	}
	address := uint64(value)
	if address < img.imageBase || address-img.imageBase > 0xffffffff {
		return 0, fmt.Errorf("VA 0x%x cannot be represented as a 32-bit RVA", address)
	}
	return uint32(address - img.imageBase), nil
}

func (img *image) readRVA(rva, size uint32) ([]byte, *pe.Section, int64, error) {
	if size == 0 {
		return nil, nil, 0, errors.New("zero-length RVA range")
	}
	start := uint64(rva)
	end := start + uint64(size)
	if end > 1<<32 || end < start {
		return nil, nil, 0, errors.New("RVA range overflows")
	}
	if end > uint64(img.optional.SizeOfImage) {
		return nil, nil, 0, fmt.Errorf("RVA range exceeds SizeOfImage 0x%x", img.optional.SizeOfImage)
	}
	var match *sectionRange
	for index := range img.sections {
		section := &img.sections[index]
		if start >= section.start && end <= section.end {
			if match != nil {
				return nil, nil, 0, errors.New("RVA range maps to multiple sections")
			}
			match = section
		}
	}
	if match == nil {
		return nil, nil, 0, errors.New("RVA range is outside every section")
	}
	if match.section.Characteristics&imageScnMemRead == 0 {
		return nil, nil, 0, fmt.Errorf("RVA range is in non-readable section %q", match.section.Name)
	}
	delta := start - match.start
	rawSize := uint64(match.section.Size)
	if delta > rawSize || uint64(size) > rawSize-delta {
		return nil, nil, 0, fmt.Errorf("RVA range is not fully backed by raw bytes in section %q", match.section.Name)
	}
	fileOffset := uint64(match.section.Offset) + delta
	if fileOffset+uint64(size) > uint64(img.fileSize) {
		return nil, nil, 0, fmt.Errorf("RVA range maps beyond end of file in section %q", match.section.Name)
	}
	data := make([]byte, int(size))
	if _, err := img.file.ReadAt(data, int64(fileOffset)); err != nil {
		return nil, nil, 0, err
	}
	return data, match.section, int64(fileOffset), nil
}

func (img *image) readCString(rva uint32, limit int) (string, error) {
	for _, entry := range img.sections {
		if uint64(rva) < entry.start || uint64(rva) >= entry.end {
			continue
		}
		if entry.section.Characteristics&imageScnMemRead == 0 {
			return "", fmt.Errorf("string RVA is in non-readable section %q", entry.section.Name)
		}
		delta := uint64(rva) - entry.start
		rawAvailable := uint64(entry.section.Size)
		if delta >= rawAvailable {
			return "", fmt.Errorf("string RVA is not raw-backed in section %q", entry.section.Name)
		}
		available := rawAvailable - delta
		virtualAvailable := entry.end - uint64(rva)
		if available > virtualAvailable {
			available = virtualAvailable
		}
		if available > uint64(limit) {
			available = uint64(limit)
		}
		bytesAtRVA := make([]byte, int(available))
		fileOffset := uint64(entry.section.Offset) + delta
		if _, err := img.file.ReadAt(bytesAtRVA, int64(fileOffset)); err != nil {
			return "", err
		}
		end := bytes.IndexByte(bytesAtRVA, 0)
		if end < 0 {
			return "", fmt.Errorf("NUL terminator not found within %d bytes in section %q", len(bytesAtRVA), entry.section.Name)
		}
		return string(bytesAtRVA[:end]), nil
	}
	return "", fmt.Errorf("string RVA 0x%08x is outside every section", rva)
}

func (img *image) validateThunks(rva uint32) error {
	const width = 8
	for index := 0; index < maxThunkEntries; index++ {
		current := uint64(rva) + uint64(index*width)
		if current > 0xffffffff {
			return errors.New("thunk RVA overflows")
		}
		data, _, _, err := img.readRVA(uint32(current), width)
		if err != nil {
			return err
		}
		entry := binary.LittleEndian.Uint64(data)
		if entry == 0 {
			return nil
		}
		if entry&(uint64(1)<<63) != 0 {
			if entry&^((uint64(1)<<63)|0xffff) != 0 || entry&0xffff == 0 {
				return fmt.Errorf("invalid ordinal thunk 0x%x", entry)
			}
			continue
		}
		if entry > 0xffffffff {
			return fmt.Errorf("import-by-name thunk exceeds RVA width: 0x%x", entry)
		}
		nameRVA := uint32(entry)
		if nameRVA > ^uint32(0)-2 {
			return fmt.Errorf("import-by-name RVA overflows when skipping the hint: 0x%08x", nameRVA)
		}
		if _, _, _, err := img.readRVA(nameRVA, 2); err != nil {
			return fmt.Errorf("import-by-name hint at RVA 0x%08x: %w", nameRVA, err)
		}
		name, err := img.readCString(nameRVA+2, maxStringSize)
		if err != nil {
			return fmt.Errorf("import-by-name string at RVA 0x%08x: %w", nameRVA+2, err)
		}
		if name == "" || strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r > 0x7e }) >= 0 {
			return fmt.Errorf("invalid import-by-name string %q", name)
		}
	}
	return fmt.Errorf("thunk terminator not found within %d entries", maxThunkEntries)
}

func (img *image) validateThunkTerminator(rva uint32) error {
	const width = 8
	for index := 0; index < maxThunkEntries; index++ {
		current := uint64(rva) + uint64(index*width)
		if current > 0xffffffff {
			return errors.New("thunk RVA overflows")
		}
		data, _, _, err := img.readRVA(uint32(current), width)
		if err != nil {
			return err
		}
		if binary.LittleEndian.Uint64(data) == 0 {
			return nil
		}
	}
	return fmt.Errorf("thunk terminator not found within %d entries", maxThunkEntries)
}

func crossCheckDebugPEImports(img *image, strictNames []string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("debug/pe ImportedSymbols cross-check panicked: %v", recovered)
		}
	}()
	symbols, err := img.pe.ImportedSymbols()
	if err != nil {
		return fmt.Errorf("debug/pe ImportedSymbols cross-check failed: %w", err)
	}
	libraries := make([]string, 0, len(symbols))
	for _, symbol := range symbols {
		separator := strings.LastIndexByte(symbol, ':')
		if separator < 0 || separator == len(symbol)-1 {
			return fmt.Errorf("debug/pe ImportedSymbols returned an unqualified symbol %q", symbol)
		}
		libraries = append(libraries, symbol[separator+1:])
	}
	libraries = uniqueSorted(libraries)
	if !sameNames(libraries, strictNames) {
		return fmt.Errorf("debug/pe cross-check disagrees with bounded RVA parser: debug/pe=%v bounded=%v", libraries, strictNames)
	}
	fmt.Printf("debug/pe ImportedSymbols cross-check: PASS (%d symbols, DLL set %v)\n", len(symbols), libraries)
	return nil
}

func writeNames(path string, names []string) error {
	content := ""
	if len(names) != 0 {
		content = strings.Join(names, "\n") + "\n"
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func printDescriptors(kind string, descriptors []importDescriptor) {
	for _, descriptor := range descriptors {
		fmt.Printf("%s Descriptor[%d]: NameRVA=0x%08x LookupTableRVA=0x%08x AddressTableRVA=0x%08x DLLName=%s\n",
			kind, descriptor.index, descriptor.nameRVA, descriptor.lookupRVA, descriptor.thunkRVA, descriptor.name)
	}
}

func uniqueSorted(names []string) []string {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[strings.ToLower(name)] = struct{}{}
	}
	result := make([]string, 0, len(set))
	for name := range set {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}

func sameNames(left, right []string) bool {
	left = uniqueSorted(left)
	right = uniqueSorted(right)
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func validModuleName(name string) bool {
	if name == "" || strings.ContainsAny(name, "/\\:") {
		return false
	}
	return strings.IndexFunc(name, func(r rune) bool { return r < 0x20 || r > 0x7e }) < 0
}
