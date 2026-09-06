// Package strictproof validates the Go toolchain and module graph used for a
// release build.
//
// The package name predates the public-source export. New validation code
// should use smoke, integration, or conformance language and must not present a
// unit check as deployment evidence.
package strictproof
