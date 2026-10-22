package jsruntime

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/dop251/goja"
)

const maxJSONDepth = 128
const maxValueTraversalDepth = 256

var (
	jsonMarshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()
	textMarshalerType = reflect.TypeOf((*encoding.TextMarshaler)(nil)).Elem()
	gojaValueType     = reflect.TypeOf((*goja.Value)(nil)).Elem()
	goStringType      = reflect.TypeOf("")
	goInt64Type       = reflect.TypeOf(int64(0))
	goFloat64Type     = reflect.TypeOf(float64(0))
)

type jsonSizeBudget struct {
	limit int
	used  int
}

func marshalBoundedInput(input any, limit int) ([]byte, error) {
	budget := jsonSizeBudget{limit: limit}
	if err := budget.value(reflect.ValueOf(input), 0, 0); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if len(encoded) > limit {
		return nil, fmt.Errorf("%w: input is %d bytes; limit is %d", ErrResourceLimit, len(encoded), limit)
	}
	return encoded, nil
}

func (b *jsonSizeBudget) add(size int) error {
	if size < 0 || b.used > b.limit || size > b.limit-b.used {
		return fmt.Errorf("%w: input exceeds %d bytes", ErrResourceLimit, b.limit)
	}
	b.used += size
	return nil
}

func (b *jsonSizeBudget) quotedString(value string) error {
	if err := b.add(2); err != nil { // opening and closing quotes
		return err
	}
	for len(value) > 0 {
		r, width := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && width == 1 {
			if err := b.add(6); err != nil { // encoding/json replaces invalid UTF-8 with \ufffd
				return err
			}
			value = value[1:]
			continue
		}
		cost := width
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			cost = 2
		case '<', '>', '&', '\u2028', '\u2029':
			cost = 6
		default:
			if r < 0x20 {
				cost = 6
			}
		}
		if err := b.add(cost); err != nil {
			return err
		}
		value = value[width:]
	}
	return nil
}

func (b *jsonSizeBudget) value(value reflect.Value, jsonDepth, traversalDepth int) error {
	if traversalDepth > maxValueTraversalDepth {
		return fmt.Errorf("%w: input value traversal exceeds %d levels", ErrResourceLimit, maxValueTraversalDepth)
	}
	if !value.IsValid() {
		return b.add(4) // null
	}
	if hasUserJSONEncoder(value.Type()) {
		return fmt.Errorf("input type %s implements a custom JSON or text encoder", value.Type())
	}

	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return b.add(4)
		}
		return b.value(value.Elem(), jsonDepth, traversalDepth+1)
	case reflect.Bool:
		if value.Bool() {
			return b.add(4)
		}
		return b.add(5)
	case reflect.String:
		return b.quotedString(value.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		var buffer [32]byte
		encoded := strconv.AppendInt(buffer[:0], value.Int(), 10)
		return b.add(len(encoded))
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		var buffer [32]byte
		encoded := strconv.AppendUint(buffer[:0], value.Uint(), 10)
		return b.add(len(encoded))
	case reflect.Float32, reflect.Float64:
		number := value.Float()
		if math.IsInf(number, 0) || math.IsNaN(number) {
			return fmt.Errorf("json: unsupported value: %s", value.Type())
		}
		bits := value.Type().Bits()
		var buffer [32]byte
		encoded := strconv.AppendFloat(buffer[:0], number, 'g', -1, bits)
		return b.add(len(encoded))
	case reflect.Array, reflect.Slice:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return b.add(4)
		}
		if value.Kind() == reflect.Slice && value.Type().Elem() == reflect.TypeOf(byte(0)) {
			if err := b.add(2); err != nil {
				return err
			}
			length := value.Len()
			groups := length / 3
			remaining := b.limit - b.used
			if groups > remaining/4 {
				return fmt.Errorf("%w: input exceeds %d bytes", ErrResourceLimit, b.limit)
			}
			encodedLength := groups * 4
			if length%3 != 0 {
				if remaining-encodedLength < 4 {
					return fmt.Errorf("%w: input exceeds %d bytes", ErrResourceLimit, b.limit)
				}
				encodedLength += 4
			}
			return b.add(encodedLength)
		}
		if jsonDepth+1 > maxJSONDepth {
			return fmt.Errorf("%w: input nesting exceeds %d levels", ErrResourceLimit, maxJSONDepth)
		}
		if err := b.add(2); err != nil { // brackets
			return err
		}
		for index := 0; index < value.Len(); index++ {
			if index > 0 {
				if err := b.add(1); err != nil {
					return err
				}
			}
			if err := b.value(value.Index(index), jsonDepth+1, traversalDepth+1); err != nil {
				return err
			}
		}
		return nil
	case reflect.Map:
		if value.IsNil() {
			return b.add(4)
		}
		if jsonDepth+1 > maxJSONDepth {
			return fmt.Errorf("%w: input nesting exceeds %d levels", ErrResourceLimit, maxJSONDepth)
		}
		if err := b.add(2); err != nil { // braces
			return err
		}
		iterator := value.MapRange()
		index := 0
		for iterator.Next() {
			if index > 0 {
				if err := b.add(1); err != nil {
					return err
				}
			}
			key, err := jsonMapKey(iterator.Key())
			if err != nil {
				return err
			}
			if err := b.quotedString(key); err != nil {
				return err
			}
			if err := b.add(1); err != nil { // colon
				return err
			}
			if err := b.value(iterator.Value(), jsonDepth+1, traversalDepth+1); err != nil {
				return err
			}
			index++
		}
		return nil
	case reflect.Struct:
		if jsonDepth+1 > maxJSONDepth {
			return fmt.Errorf("%w: input nesting exceeds %d levels", ErrResourceLimit, maxJSONDepth)
		}
		if err := b.add(2); err != nil { // braces
			return err
		}
		index := 0
		for fieldIndex := 0; fieldIndex < value.NumField(); fieldIndex++ {
			field := value.Type().Field(fieldIndex)
			if field.PkgPath != "" {
				if field.Anonymous {
					return fmt.Errorf("input struct %s has an unexported embedded field", value.Type())
				}
				continue
			}
			tag := field.Tag.Get("json")
			parts := strings.Split(tag, ",")
			if len(parts) > 0 && parts[0] == "-" {
				continue
			}
			fieldValue := value.Field(fieldIndex)
			if (hasJSONOption(parts[1:], "omitempty") && isEmptyJSONValue(fieldValue)) ||
				(hasJSONOption(parts[1:], "omitzero") && fieldValue.IsZero()) {
				continue
			}
			name := field.Name
			if len(parts) > 0 && parts[0] != "" {
				name = parts[0]
			}
			if len(parts) > 0 && parts[0] != "" && !validJSONFieldName(parts[0]) {
				name = field.Name
			}
			if index > 0 {
				if err := b.add(1); err != nil {
					return err
				}
			}
			if err := b.quotedString(name); err != nil {
				return err
			}
			if err := b.add(1); err != nil { // colon
				return err
			}
			valueStart := b.used
			if err := b.value(fieldValue, jsonDepth+1, traversalDepth+1); err != nil {
				return err
			}
			if hasJSONOption(parts[1:], "string") && isQuotedJSONScalar(fieldValue) {
				delta := b.used - valueStart
				remaining := b.limit - b.used
				if remaining < 2 || delta > remaining-2 {
					return fmt.Errorf("%w: input exceeds %d bytes", ErrResourceLimit, b.limit)
				}
				if err := b.add(delta + 2); err != nil {
					return err
				}
			}
			index++
		}
		return nil
	default:
		return fmt.Errorf("json: unsupported type: %s", value.Type())
	}
}

func isEmptyJSONValue(value reflect.Value) bool {
	switch value.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return value.Len() == 0
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.Interface, reflect.Pointer:
		return value.IsZero()
	default:
		return false
	}
}

func hasJSONOption(options []string, option string) bool {
	for _, candidate := range options {
		if candidate == option {
			return true
		}
	}
	return false
}

func isQuotedJSONScalar(value reflect.Value) bool {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return false
		}
		value = value.Elem()
	}
	if !value.IsValid() {
		return false
	}
	switch value.Kind() {
	case reflect.Bool, reflect.String,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

func hasUserJSONEncoder(typeOf reflect.Type) bool {
	if typeOf.Implements(jsonMarshalerType) || typeOf.Implements(textMarshalerType) {
		return true
	}
	if typeOf.Kind() != reflect.Pointer {
		pointerType := reflect.PointerTo(typeOf)
		return pointerType.Implements(jsonMarshalerType) || pointerType.Implements(textMarshalerType)
	}
	return false
}

func jsonMapKey(key reflect.Value) (string, error) {
	if hasUserJSONEncoder(key.Type()) {
		return "", fmt.Errorf("json: map key type %s implements a custom text encoder", key.Type())
	}
	switch key.Kind() {
	case reflect.String:
		return key.String(), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(key.Int(), 10), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(key.Uint(), 10), nil
	default:
		return "", fmt.Errorf("json: unsupported map key type: %s", key.Type())
	}
}

func validJSONFieldName(name string) bool {
	if name == "" {
		return false
	}
	for _, character := range name {
		if character == '"' || character == '\\' || character < 0x20 {
			return false
		}
		if strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", character) || unicode.IsLetter(character) || unicode.IsDigit(character) {
			continue
		}
		return false
	}
	return true
}

func outputSizeError(err error) bool {
	return errors.Is(err, errOutputLimit)
}

func limitedJSStringSize(vm *goja.Runtime, value goja.Value, limit int) (int, error) {
	if stringValue, ok := value.(goja.String); ok {
		return jsStringJSONSize(stringValue, limit)
	}
	if value.ExportType() != goStringType {
		return 0, fmt.Errorf("expected JavaScript string, got %s", value.ExportType())
	}
	length := value.ToObject(vm).Get("length").ToInteger()
	if length < 0 || length > int64(limit) {
		return 0, errOutputLimit
	}
	text, ok := value.Export().(string)
	if !ok {
		return 0, errors.New("JavaScript string export returned a non-string value")
	}
	size := goStringJSONSize(text, limit)
	if size > limit {
		return 0, errOutputLimit
	}
	return size, nil
}

func isPlainArray(value goja.Value) bool {
	object, ok := value.(*goja.Object)
	if !ok {
		return false
	}
	typeOf := object.ExportType()
	return typeOf.Kind() == reflect.Slice && typeOf.Elem() == gojaValueType
}

var errOutputLimit = errors.New("javascript output exceeds configured limit")

type outputSizeBudget struct {
	limit int
	used  int
}

type outputJSONNumber struct {
	encodedSize int
}

type outputJSONString struct {
	encodedSize int
}

func (b *outputSizeBudget) accept(keySize int, value any, root, arrayElement bool) error {
	if !root && !arrayElement {
		if err := b.add(keySize); err != nil {
			return err
		}
		if err := b.add(2); err != nil { // colon and a conservative comma
			return err
		}
	} else if !root && arrayElement {
		if err := b.add(1); err != nil { // a conservative comma
			return err
		}
	}

	switch typed := value.(type) {
	case outputJSONString:
		return b.add(typed.encodedSize)
	case string:
		return b.add(goStringJSONSize(typed, b.limit))
	case outputJSONNumber:
		return b.add(typed.encodedSize)
	case int64:
		var buffer [32]byte
		return b.add(len(strconv.AppendInt(buffer[:0], typed, 10)))
	case float64:
		if math.IsInf(typed, 0) || math.IsNaN(typed) {
			return b.add(4) // JSON.stringify serializes non-finite numbers as null
		}
		var buffer [32]byte
		return b.add(len(strconv.AppendFloat(buffer[:0], typed, 'g', -1, 64)))
	case bool:
		if typed {
			return b.add(4)
		}
		return b.add(5)
	case nil:
		return b.add(4)
	case *goja.Object:
		return b.add(2) // nested object or array delimiters
	default:
		// Undefined and symbols are omitted by JSON.stringify. BigInt will be
		// rejected by JSON.stringify itself with its normal conversion error.
		return nil
	}
}

func jsStringJSONSize(value goja.String, limit int) (int, error) {
	length := value.Length()
	if length > limit {
		return 0, errOutputLimit
	}
	size := 2 // JSON quotes
	if size > limit {
		return 0, errOutputLimit
	}
	for index := 0; index < length; index++ {
		unit := value.CharAt(index)
		cost := 0
		switch unit {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			cost = 2
		case '<', '>', '&', '\u2028', '\u2029':
			cost = 6
		default:
			switch {
			case unit < 0x20:
				cost = 6
			case unit < 0x80:
				cost = 1
			case unit < 0x800:
				cost = 2
			case unit >= 0xD800 && unit <= 0xDBFF:
				if index+1 < length {
					next := value.CharAt(index + 1)
					if next >= 0xDC00 && next <= 0xDFFF {
						cost = 4
						index++
					} else {
						cost = 6
					}
				} else {
					cost = 6
				}
			case unit >= 0xDC00 && unit <= 0xDFFF:
				cost = 6
			default:
				cost = 3
			}
		}
		if cost > limit-size {
			return 0, errOutputLimit
		}
		size += cost
	}
	return size, nil
}

func goStringJSONSize(value string, limit int) int {
	size := 2
	for len(value) > 0 {
		r, width := utf8.DecodeRuneInString(value)
		if r == utf8.RuneError && width == 1 {
			size += 6
			value = value[1:]
			if size > limit {
				return size
			}
			continue
		}
		cost := width
		switch r {
		case '"', '\\', '\b', '\f', '\n', '\r', '\t':
			cost = 2
		case '<', '>', '&', '\u2028', '\u2029':
			cost = 6
		default:
			if r < 0x20 {
				cost = 6
			} else if r == utf8.RuneError {
				cost += 3
			}
		}
		size += cost
		if size > limit {
			return size
		}
		value = value[width:]
	}
	return size
}

func (b *outputSizeBudget) add(size int) error {
	if size < 0 || b.used > b.limit || size > b.limit-b.used {
		return errOutputLimit
	}
	b.used += size
	return nil
}
