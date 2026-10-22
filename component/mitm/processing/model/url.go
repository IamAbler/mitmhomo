package model

import (
	"math"
	"net/url"
	"strconv"
	"strings"
)

type URLProfile uint8

const (
	// AbsoluteURL accepts an absolute hierarchical URL. Protocol policy belongs
	// to an explicitly selected profile, not to the value's raw query storage.
	AbsoluteURL URLProfile = iota
	MITMHTTPS
)

// URLValue preserves the supplied spelling and query. No getter exposes a URL
// pointer or a mutable Query map. Immutable scalar strings borrow its lease.
type URLValue struct {
	raw, scheme, host, path, escapedPath, rawQuery string
	forceQuery                                     bool
	profile                                        URLProfile
	lease                                          *CopyLease
}

func ParseURL(lease *CopyLease, raw string, profile URLProfile) (URLValue, error) {
	if profile > MITMHTTPS || len(raw) == 0 || strings.ContainsAny(raw, "\r\n\x00") {
		return URLValue{}, ErrInvalid
	}
	if int64(len(raw)) > (math.MaxInt64-256)/8 {
		return URLValue{}, ErrResourceLimit
	}
	var out URLValue
	err := lease.allocate(int64(len(raw))*8+256, func() error {
		u, err := url.Parse(raw)
		if err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "" {
			return ErrInvalid
		}
		if _, err := url.QueryUnescape(u.RawQuery); err != nil {
			return ErrInvalid
		}
		if profile == MITMHTTPS && (!strings.EqualFold(u.Scheme, "https") || u.User != nil || u.Fragment != "" || u.RawFragment != "") {
			return ErrInvalid
		}
		if profile == MITMHTTPS {
			if u.Hostname() == "" {
				return ErrInvalid
			}
			if port := u.Port(); port != "" {
				n, err := strconv.ParseUint(port, 10, 16)
				if err != nil || n == 0 {
					return ErrInvalid
				}
			}
		}
		out = URLValue{raw: strings.Clone(raw), scheme: strings.Clone(u.Scheme), host: strings.Clone(u.Host), path: strings.Clone(u.Path), escapedPath: strings.Clone(u.EscapedPath()), rawQuery: strings.Clone(u.RawQuery), forceQuery: u.ForceQuery, profile: profile, lease: lease}
		return nil
	})
	if err != nil {
		return URLValue{}, err
	}
	return out, nil
}
func (u URLValue) String() string      { return u.raw }
func (u URLValue) Scheme() string      { return u.scheme }
func (u URLValue) Host() string        { return u.host }
func (u URLValue) Path() string        { return u.path }
func (u URLValue) EscapedPath() string { return u.escapedPath }
func (u URLValue) RawQuery() string    { return u.rawQuery }
func (u URLValue) ForceQuery() bool    { return u.forceQuery }
func (u URLValue) clone(to *CopyLease) (URLValue, error) {
	if u.raw == "" {
		return URLValue{}, ErrInvalid
	}
	unpin, err := u.lease.pin()
	if err != nil {
		return URLValue{}, err
	}
	defer unpin()
	return ParseURL(to, u.raw, u.profile)
}
