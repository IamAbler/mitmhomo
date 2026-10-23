package gojaprocessor

import (
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

// boundedJSONSize mirrors encoding/json's string escaping and stops as soon as
// the input cannot fit. The runtime performs the actual JSON serialization;
// this preflight keeps input-size errors distinct from script-output limits.
func boundedJSONSize(value any, limit int) (int, error) {
	if limit < 0 {
		return 0, fmt.Errorf("negative JSON byte limit")
	}
	size := 0
	add := func(n int) error {
		if n < 0 || size > limit-n {
			return fmt.Errorf("serialized input exceeds %d bytes", limit)
		}
		size += n
		return nil
	}
	var visit func(any) error
	visit = func(value any) error {
		switch item := value.(type) {
		case nil:
			return add(4)
		case bool:
			if item {
				return add(4)
			}
			return add(5)
		case string:
			return add(jsonStringSize(item))
		case int:
			return add(len(strconv.Itoa(item)))
		case int64:
			return add(len(strconv.FormatInt(item, 10)))
		case uint64:
			return add(len(strconv.FormatUint(item, 10)))
		case float64:
			if math.IsNaN(item) || math.IsInf(item, 0) {
				return add(4)
			}
			return add(len(strconv.FormatFloat(item, 'g', -1, 64)))
		case []string:
			if err := add(2); err != nil {
				return err
			}
			for i, text := range item {
				if i != 0 {
					if err := add(1); err != nil {
						return err
					}
				}
				if err := visit(text); err != nil {
					return err
				}
			}
			return nil
		case []any:
			if err := add(2); err != nil {
				return err
			}
			for i, child := range item {
				if i != 0 {
					if err := add(1); err != nil {
						return err
					}
				}
				if err := visit(child); err != nil {
					return err
				}
			}
			return nil
		case map[string]any:
			if err := add(2); err != nil {
				return err
			}
			first := true
			for key, child := range item {
				if !first {
					if err := add(1); err != nil {
						return err
					}
				}
				first = false
				if err := add(jsonStringSize(key) + 1); err != nil { // key and colon
					return err
				}
				if err := visit(child); err != nil {
					return err
				}
			}
			return nil
		default:
			return fmt.Errorf("unsupported JSON input type %T", value)
		}
	}
	if err := visit(value); err != nil {
		return size, err
	}
	return size, nil
}

func jsonStringSize(value string) int {
	size := 2 // quotes
	for index := 0; index < len(value); {
		r, width := utf8.DecodeRuneInString(value[index:])
		if width == 0 {
			break
		}
		if r == utf8.RuneError && width == 1 {
			size += 3 // encoding/json replaces malformed UTF-8 with U+FFFD
			index++
			continue
		}
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			size += 2
		case '<', '>', '&', '\u2028', '\u2029':
			size += 6 // encoding/json's default HTML-safe escaping
		default:
			if r < 0x20 {
				size += 6
			} else {
				size += width
			}
		}
		index += width
	}
	return size
}
