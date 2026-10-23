// Package quickjs is a small, optional adapter around the official QuickJS C
// sources vendored in native/.
//
// Build with the quickjs tag and cgo enabled to use the engine. Without that
// configuration, NewRuntime returns ErrUnavailable; the package never falls
// back to another JavaScript engine.
package quickjs
