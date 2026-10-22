package model

import (
	"math"
	"net/textproto"
	"strings"
)

type HeaderField struct {
	Name   string
	Values []string
}

// HeaderBlock is immutable. Duplicate case-insensitive names are grouped at
// their first position, with values appended in source order. A nil/empty value
// list is present-but-empty; it is not an absent field or one empty string.
type HeaderBlock struct {
	fields []HeaderField
	lease  *CopyLease
}

func validName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c))) {
			return false
		}
	}
	return true
}

func validValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 32 && s[i] != '\t' || s[i] == 127 {
			return false
		}
	}
	return true
}

func headerCharge(fields []HeaderField) (int64, error) {
	n := int64(128)
	for _, f := range fields {
		if !validName(f.Name) {
			return 0, ErrInvalid
		}
		add := int64(len(f.Name))*2 + 128
		for _, v := range f.Values {
			if !validValue(v) {
				return 0, ErrInvalid
			}
			if int64(len(v)) > math.MaxInt64-add-32 {
				return 0, ErrResourceLimit
			}
			add += int64(len(v)) + 32
		}
		if add > math.MaxInt64-n {
			return 0, ErrResourceLimit
		}
		n += add
	}
	return n, nil
}

func NewHeaderBlock(lease *CopyLease, fields []HeaderField) (HeaderBlock, error) {
	n, err := headerCharge(fields)
	if err != nil {
		return HeaderBlock{}, err
	}
	var out []HeaderField
	err = lease.allocate(n, func() error {
		out = make([]HeaderField, 0, len(fields))
		indices := make(map[string]int, len(fields))
		for _, f := range fields {
			name := textproto.CanonicalMIMEHeaderKey(f.Name)
			index, ok := indices[name]
			if !ok {
				index = len(out)
				indices[name] = index
				out = append(out, HeaderField{Name: strings.Clone(name)})
			}
			for _, v := range f.Values {
				out[index].Values = append(out[index].Values, strings.Clone(v))
			}
		}
		return nil
	})
	if err != nil {
		return HeaderBlock{}, err
	}
	return HeaderBlock{fields: out, lease: lease}, nil
}

func (h HeaderBlock) Len() int { return len(h.fields) }

func (h HeaderBlock) Values(name string) ([]string, bool, error) {
	if h.lease == nil {
		return nil, false, nil
	} // Valid empty zero value.
	var field *HeaderField
	for i := range h.fields {
		if strings.EqualFold(name, h.fields[i].Name) {
			field = &h.fields[i]
			break
		}
	}
	if field == nil {
		unpin, err := h.lease.pin()
		if err != nil {
			return nil, false, err
		}
		unpin()
		return nil, false, nil
	}
	n := int64(128 + len(field.Values)*32)
	for _, v := range field.Values {
		n += int64(len(v))
	}
	var out []string
	err := h.lease.allocate(n, func() error {
		out = make([]string, len(field.Values))
		for i, v := range field.Values {
			out[i] = strings.Clone(v)
		}
		return nil
	})
	if err != nil {
		return nil, false, err
	}
	return out, true, err
}

func (h HeaderBlock) Entries() ([]HeaderField, error) {
	if h.lease == nil {
		return nil, nil
	}
	copy, err := h.Clone(h.lease)
	if err != nil {
		return nil, err
	}
	return copy.fields, nil // The new allocation is not an internal stored block.
}

func (h HeaderBlock) Clone(to *CopyLease) (HeaderBlock, error) {
	if h.lease != nil {
		unpin, err := h.lease.pin()
		if err != nil {
			return HeaderBlock{}, err
		}
		defer unpin()
	}
	return NewHeaderBlock(to, h.fields)
}

// HeaderEdit is only a data vocabulary for future result validation. No result
// or pipeline execution is implemented here. ReplaceAll uses Block exclusively.
type HeaderOpKind uint8

const (
	HeaderSet HeaderOpKind = iota + 1
	HeaderAdd
	HeaderRemove
	HeaderReplaceAll
)

type HeaderEdit struct {
	Kind   HeaderOpKind
	Name   string
	Values []string
	Block  HeaderBlock
}

type TrailerAvailability uint8

const (
	TrailerUnavailable TrailerAvailability = iota
	TrailerPending
	TrailerComplete
)

type TrailerView struct {
	availability     TrailerAvailability
	declared, values HeaderBlock
}

func NewTrailerView(state TrailerAvailability, declared, values HeaderBlock) (TrailerView, error) {
	if state > TrailerComplete || state != TrailerComplete && values.Len() != 0 || state == TrailerUnavailable && declared.Len() != 0 {
		return TrailerView{}, ErrInvalid
	}
	for _, field := range values.fields {
		found := false
		for _, name := range declared.fields {
			if name.Name == field.Name {
				found = true
				break
			}
		}
		if !found {
			return TrailerView{}, ErrInvalid
		}
	}
	return TrailerView{state, declared, values}, nil
}
func (t TrailerView) Availability() TrailerAvailability { return t.availability }
func (t TrailerView) Declared() HeaderBlock             { return t.declared }
func (t TrailerView) Values() (HeaderBlock, error) {
	if t.availability != TrailerComplete {
		return HeaderBlock{}, ErrBodyUnavailable
	}
	return t.values, nil
}
func (t TrailerView) clone(to *CopyLease) (TrailerView, error) {
	d, err := t.declared.Clone(to)
	if err != nil {
		return TrailerView{}, err
	}
	v, err := t.values.Clone(to)
	if err != nil {
		return TrailerView{}, err
	}
	return NewTrailerView(t.availability, d, v)
}
