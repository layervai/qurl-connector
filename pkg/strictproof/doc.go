// Package strictproof holds fail-closed decision logic used by release and
// protocol validation. Verifiers consume explicit observations, never infer
// missing values, and return an error that identifies the failed invariant.
//
// The package name predates the public-source export. New validation code
// should use smoke, integration, or conformance language and must not present a
// unit check as deployment evidence.
package strictproof
