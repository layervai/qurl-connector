package agentstate

import (
	"encoding/binary"
	"testing"
)

func TestInheritedCRTHandle(t *testing.T) {
	for _, width := range []int{4, 8} {
		table := make([]byte, 4+4*(1+width))
		binary.LittleEndian.PutUint32(table, 4)
		table[7] = 9 // FOPEN | FPIPE
		binary.LittleEndian.PutUint32(table[8+3*width:], 1234)
		got, err := inheritedCRTHandle(table, 3, width)
		if err != nil || got != 1234 {
			t.Fatalf("width %d: handle %d, err %v", width, got, err)
		}
		for _, fd := range []int{-1, 0, 1, 2, 4, 999} {
			if _, err := inheritedCRTHandle(table, fd, width); err == nil {
				t.Fatalf("accepted fd %d", fd)
			}
		}
		for n := range len(table) {
			if _, err := inheritedCRTHandle(table[:n], 3, width); err == nil {
				t.Fatalf("accepted length %d", n)
			}
		}
		table[7] = 1
		if _, err := inheritedCRTHandle(table, 3, width); err == nil {
			t.Fatal("accepted non-pipe")
		}
	}
}

func TestInheritedCRTHandleRejectsMalformedTables(t *testing.T) {
	table := make([]byte, 4+4*9)
	binary.LittleEndian.PutUint32(table, 4)
	table[7] = 9
	for _, handle := range []uint64{0, ^uint64(0), ^uint64(0) - 1, uint64(^uint32(0))} {
		binary.LittleEndian.PutUint64(table[32:], handle)
		if _, err := inheritedCRTHandle(table, 3, 8); err == nil {
			t.Fatalf("accepted invalid handle %d", handle)
		}
	}
	binary.LittleEndian.PutUint64(table[32:], 1234)
	for _, width := range []int{0, 1, 16} {
		if _, err := inheritedCRTHandle(table, 3, width); err == nil {
			t.Fatalf("accepted width %d", width)
		}
	}
	for _, count := range []uint32{0, 3, 256, ^uint32(0)} {
		binary.LittleEndian.PutUint32(table, count)
		if _, err := inheritedCRTHandle(table, 3, 8); err == nil {
			t.Fatalf("accepted count %d", count)
		}
	}
}
