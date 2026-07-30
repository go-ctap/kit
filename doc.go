// Package ctapkit provides the public runtime facade for CTAP/FIDO2 operations.
//
// Operation methods that return (T, error) return the zero value of T whenever
// error is non-nil. An error does not imply that an authenticator command had no
// effect: progress events already emitted and state changes already performed
// remain observable.
package ctapkit
