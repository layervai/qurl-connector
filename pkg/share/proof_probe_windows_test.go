//go:build windows

package share

// Peak RSS and the descriptor table are not measured on Windows; the proof
// reports them as unavailable there.
func proofPeakRSSBytes() (uint64, bool) { return 0, false }

func proofOpenFDs() (int, bool) { return 0, false }
