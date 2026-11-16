package agentstate

import (
	"encoding/binary"
	"errors"
)

// TODO(upstream-contract): libuv process-stdio.c passes this CRT table in
// STARTUPINFO.lpReserved2: uint32 count, count flags, then count native handles.
func inheritedCRTHandle(table []byte, fd, width int) (uintptr, error) {
	if len(table) < 4 || (width != 4 && width != 8) || fd < 3 {
		return 0, errors.New("invalid inherited pipe table")
	}
	count := int(binary.LittleEndian.Uint32(table))
	if count > 255 || fd >= count || len(table) != 4+count*(1+width) || table[4+fd] != 9 {
		return 0, errors.New("inherited descriptor is not an open pipe")
	}
	offset := 4 + count + fd*width
	value := uint64(binary.LittleEndian.Uint32(table[offset:]))
	if width == 8 {
		value = binary.LittleEndian.Uint64(table[offset:])
	}
	if value == 0 || value == uint64(^uint32(0)) || value == ^uint64(0) || value == ^uint64(0)-1 {
		return 0, errors.New("invalid inherited pipe handle")
	}
	return uintptr(value), nil
}
