package archive

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// maxCentralDirBytes caps the central directory that archive/zip reads into
// memory. A variable so tests can lower it.
var maxCentralDirBytes uint64 = 64 << 20

const (
	eocdSig        = 0x06054b50
	eocdLen        = 22
	zip64LocSig    = 0x07064b50
	zip64LocLen    = 20
	zip64EOCDSig   = 0x06064b50
	centralSig     = 0x02014b50
	centralHdrLen  = 46
	maxCommentLen  = 0xffff
	zip64EOCDBytes = 56
)

// endRecord is what the end records declare.
type endRecord struct {
	entries uint64
	size    uint64
	offset  uint64
	endPos  uint64 // where the central directory must end: the EOCD, or the ZIP64 end record
	zip64   bool
}

// readEnd reads the end records the way archive/zip does: ZIP64 values are
// used only when the EOCD holds the ZIP64 marker values.
func readEnd(f *os.File, size int64) (endRecord, error) {
	n := min(size, eocdLen+maxCommentLen)
	buf := make([]byte, n)
	if _, err := f.ReadAt(buf, size-n); err != nil && err != io.EOF {
		return endRecord{}, err
	}
	at := -1
	for i := len(buf) - eocdLen; i >= 0; i-- {
		if binary.LittleEndian.Uint32(buf[i:]) == eocdSig {
			at = i
			break
		}
	}
	if at < 0 {
		return endRecord{}, errors.New("not a zip file: no end of central directory")
	}
	e := buf[at:]
	eocdPos := uint64(size - n + int64(at))
	end := endRecord{
		entries: uint64(binary.LittleEndian.Uint16(e[10:])),
		size:    uint64(binary.LittleEndian.Uint32(e[12:])),
		offset:  uint64(binary.LittleEndian.Uint32(e[16:])),
		endPos:  eocdPos,
	}
	if end.entries != 0xffff && end.size != 0xffff && end.offset != 0xffffffff {
		return end, nil
	}
	if eocdPos < zip64LocLen {
		return end, nil
	}
	var loc [zip64LocLen]byte
	if _, err := f.ReadAt(loc[:], int64(eocdPos)-zip64LocLen); err != nil {
		return endRecord{}, err
	}
	if binary.LittleEndian.Uint32(loc[:]) != zip64LocSig {
		return end, nil
	}
	recAt := binary.LittleEndian.Uint64(loc[8:])
	if recAt > uint64(size) {
		return endRecord{}, errors.New("bad zip64 locator")
	}
	var rec [zip64EOCDBytes]byte
	if _, err := f.ReadAt(rec[:], int64(recAt)); err != nil {
		return endRecord{}, fmt.Errorf("read zip64 end record: %w", err)
	}
	if binary.LittleEndian.Uint32(rec[:]) != zip64EOCDSig {
		return endRecord{}, errors.New("bad zip64 end record")
	}
	return endRecord{
		entries: binary.LittleEndian.Uint64(rec[32:]),
		size:    binary.LittleEndian.Uint64(rec[40:]),
		offset:  binary.LittleEndian.Uint64(rec[48:]),
		endPos:  recAt,
		zip64:   true,
	}, nil
}

// checkCentralDir checks the central directory before archive/zip reads it.
// The directory must end exactly where the end record starts, so the base
// offset archive/zip computes (end - size - offset) is 0 and it reads the
// same bytes we walk. The walk covers exactly [offset, offset+size), record
// by record; it stops at more than maxFiles records, and the record count
// must match the end record.
func checkCentralDir(path string, maxFiles int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	end, err := readEnd(f, fi.Size())
	if err != nil {
		return err
	}
	if end.offset > end.endPos || end.size != end.endPos-end.offset {
		return errors.New("archive has data before or inside the central directory")
	}
	if end.size > maxCentralDirBytes {
		return fmt.Errorf("zip central directory is larger than %d bytes", maxCentralDirBytes)
	}
	r := bufio.NewReader(io.NewSectionReader(f, int64(end.offset), int64(end.size)))
	var count, read uint64
	hdr := make([]byte, centralHdrLen)
	for read < end.size {
		if _, err := io.ReadFull(r, hdr); err != nil {
			return errors.New("truncated central directory")
		}
		if binary.LittleEndian.Uint32(hdr) != centralSig {
			return errors.New("archive has data before or inside the central directory")
		}
		rest := int64(binary.LittleEndian.Uint16(hdr[28:])) + int64(binary.LittleEndian.Uint16(hdr[30:])) + int64(binary.LittleEndian.Uint16(hdr[32:]))
		if _, err := io.CopyN(io.Discard, r, rest); err != nil {
			return errors.New("truncated central directory")
		}
		count++
		read += centralHdrLen + uint64(rest)
		if count > uint64(maxFiles) {
			return fmt.Errorf("zip has more than %d entries", maxFiles)
		}
	}
	if read != end.size {
		return errors.New("truncated central directory")
	}
	got := count
	if !end.zip64 {
		got %= 1 << 16
	}
	if got != end.entries {
		return fmt.Errorf("zip end record declares %d entries, central directory has %d", end.entries, count)
	}
	return nil
}
