package model

import (
	"errors"
	"reflect"
	"testing"
)

func TestHeaderValuesCloneAndPresence(t *testing.T) {
	l := testLedger(t, -1)
	s := testLease(t, l)
	source := []HeaderField{{"set-cookie", []string{"a=1"}}, {"Set-Cookie", []string{"b=2", ""}}, {"Empty", nil}, {"X-Empty", []string{""}}}
	h, err := NewHeaderBlock(s, source)
	if err != nil {
		t.Fatal(err)
	}
	source[0].Values[0] = "changed"
	values, present, err := h.Values("SET-cookie")
	if err != nil || !present || !reflect.DeepEqual(values, []string{"a=1", "b=2", ""}) {
		t.Fatalf("%v %t %v", values, present, err)
	}
	values[0] = "mutated"
	values, _, _ = h.Values("Set-Cookie")
	if values[0] != "a=1" {
		t.Fatal("getter aliases internal values")
	}
	values, present, err = h.Values("empty")
	if err != nil || !present || len(values) != 0 {
		t.Fatal("present empty lost")
	}
	values, present, err = h.Values("missing")
	if err != nil || present || values != nil {
		t.Fatal("absent lost")
	}
	values, present, _ = h.Values("x-empty")
	if !present || len(values) != 1 || values[0] != "" {
		t.Fatal("empty value lost")
	}
	entries, err := h.Entries()
	if err != nil {
		t.Fatal(err)
	}
	entries[0].Values[0] = "entries mutated"
	entries[1].Name = "Changed"
	other := NewCopyLease(l)
	defer other.Close()
	cloned, err := h.Clone(other)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	values, _, err = cloned.Values("set-cookie")
	if err != nil || values[0] != "a=1" {
		t.Fatal("clone not independent")
	}
	if _, _, err = h.Values("set-cookie"); !errors.Is(err, ErrReleased) {
		t.Fatal(err)
	}
}

func TestHeaderValidationAndCopyBudget(t *testing.T) {
	l := testLedger(t, 4096)
	s := testLease(t, l)
	for _, f := range []HeaderField{{"", nil}, {"Bad Name", nil}, {":authority", nil}, {"X", []string{"a\r\nb"}}, {"X", []string{"\x00"}}, {"X", []string{"\x7f"}}} {
		before := l.Current()
		if _, err := NewHeaderBlock(s, []HeaderField{f}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("%+v: %v", f, err)
		}
		if l.Current() != before {
			t.Fatal("invalid header charged")
		}
	}
	h, err := NewHeaderBlock(s, []HeaderField{{"X", []string{"value\tallowed"}}})
	if err != nil {
		t.Fatal(err)
	}
	limited := false
	for i := 0; i < 100; i++ {
		if _, _, err = h.Values("X"); errors.Is(err, ErrResourceLimit) {
			limited = true
			break
		} else if err != nil {
			t.Fatal(err)
		}
	}
	if !limited {
		t.Fatal("repeated copies bypass budget")
	}
	before := l.Current()
	if _, err := h.Clone(NewCopyLease(testLedger(t, 1))); !errors.Is(err, ErrResourceLimit) {
		t.Fatal(err)
	}
	if l.Current() != before {
		t.Fatal("source charge changed")
	}
}

func TestTrailerAvailabilityAndIsolation(t *testing.T) {
	l := testLedger(t, -1)
	s := testLease(t, l)
	d, _ := NewHeaderBlock(s, []HeaderField{{"X-End", nil}})
	v, _ := NewHeaderBlock(s, []HeaderField{{"X-End", []string{"done"}}})
	pending, err := NewTrailerView(TrailerPending, d, HeaderBlock{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pending.Values(); !errors.Is(err, ErrBodyUnavailable) {
		t.Fatal("pending values exposed")
	}
	if _, err := NewTrailerView(TrailerPending, d, v); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := NewTrailerView(TrailerComplete, HeaderBlock{}, v); !errors.Is(err, ErrInvalid) {
		t.Fatal("undeclared value accepted")
	}
	complete, err := NewTrailerView(TrailerComplete, d, v)
	if err != nil {
		t.Fatal(err)
	}
	copyLease := testLease(t, l)
	copy, err := complete.clone(copyLease)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := copy.Values()
	values, _, _ := block.Values("X-End")
	values[0] = "mutation"
	original, _ := complete.Values()
	values, _, _ = original.Values("X-End")
	if values[0] != "done" {
		t.Fatal("trailer alias")
	}
}

func TestURLSpellingProfilesAndSnapshot(t *testing.T) {
	l := testLedger(t, -1)
	s := testLease(t, l)
	for _, raw := range []string{"https://example.test/a%2Fb?b=2&a=&b=1&a&z=%2f", "https://example.test/empty?", "https://[::1]:443/%2f%2F?q=+&q=%20"} {
		u, err := ParseURL(s, raw, MITMHTTPS)
		if err != nil {
			t.Fatal(err)
		}
		if u.String() != raw {
			t.Fatal("URL spelling changed")
		}
		v, err := u.clone(testLease(t, l))
		if err != nil || v.String() != raw || v.RawQuery() != u.RawQuery() || v.ForceQuery() != u.ForceQuery() {
			t.Fatal("URL clone changed")
		}
	}
	u, err := ParseURL(s, "https://example.test/a%2Fb?x=&x&x=2", MITMHTTPS)
	if err != nil || u.Path() != "/a/b" || u.EscapedPath() != "/a%2Fb" || u.RawQuery() != "x=&x&x=2" {
		t.Fatal("URL components lost")
	}
	for _, raw := range []string{"relative", "http://example.test/", "https://u:p@example.test/", "https://example.test/#x", "https://example.test:65536/", "https://example.test/?x=%zz", "https://example.test/%zz", "https:///x"} {
		before := l.Current()
		if _, err := ParseURL(s, raw, MITMHTTPS); err == nil {
			t.Fatalf("accepted %q", raw)
		}
		if l.Current() != before {
			t.Fatal("failed URL allocation leaked")
		}
	}
	if _, err := ParseURL(s, "http://example.test/", AbsoluteURL); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseURL(s, "custom://example.test/path?x=1&x=2", AbsoluteURL); err != nil {
		t.Fatal(err)
	}
}
