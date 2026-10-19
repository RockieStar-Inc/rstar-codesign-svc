package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/testutil"
)

var lim = Limits{MaxExpandedBytes: 1 << 20, MaxFiles: 100}

func writeZip(t *testing.T, data []byte) (src, dst string) {
	t.Helper()
	dir := t.TempDir()
	src = filepath.Join(dir, "in.zip")
	if err := os.WriteFile(src, data, 0o600); err != nil {
		t.Fatal(err)
	}
	dst = filepath.Join(dir, "out")
	if err := os.Mkdir(dst, 0o700); err != nil {
		t.Fatal(err)
	}
	return src, dst
}

func unzipEntries(t *testing.T, entries []testutil.Entry, l Limits) (string, error) {
	t.Helper()
	src, dst := writeZip(t, testutil.Zip(t, entries))
	return dst, Unzip(src, dst, l)
}

func TestUnzipValidApp(t *testing.T) {
	entries := append(testutil.ElectronLikeApp("com.example.app"),
		testutil.Entry{Path: "__MACOSX/Example.app/._Info.plist", Data: []byte("x")},
		testutil.Entry{Path: ".DS_Store", Data: []byte("x")},
		testutil.Entry{Path: "Example.app/Contents/._junk", Data: []byte("x")},
	)
	dst, err := unzipEntries(t, entries, lim)
	if err != nil {
		t.Fatal(err)
	}
	app, err := FindApp(dst)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckFrameworks(app); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		exec bool
	}{
		{"Contents/MacOS/Example", true},
		{"Contents/Resources/node/bin/node", true},
		{"Contents/Resources/app.asar", false},
	}
	for _, c := range cases {
		fi, err := os.Stat(filepath.Join(app, c.path))
		if err != nil {
			t.Fatal(err)
		}
		if (fi.Mode().Perm()&0o111 != 0) != c.exec {
			t.Errorf("%s: mode %v", c.path, fi.Mode())
		}
		if fi.Mode().Perm()&0o022 != 0 {
			t.Errorf("%s: group/world writable", c.path)
		}
	}
	link := filepath.Join(app, "Contents/Frameworks/Electron Framework.framework/Versions/Current")
	if target, err := os.Readlink(link); err != nil || target != "A" {
		t.Fatalf("symlink: %q %v", target, err)
	}
	for _, p := range []string{"__MACOSX", ".DS_Store", "Example.app/Contents/._junk"} {
		if _, err := os.Lstat(filepath.Join(dst, p)); !os.IsNotExist(err) {
			t.Fatalf("%s was extracted", p)
		}
	}
}

func TestUnzipRejects(t *testing.T) {
	cases := []struct {
		name    string
		entries []testutil.Entry
		want    string
	}{
		{"traversal", []testutil.Entry{{Path: "../evil", Data: []byte("x")}}, "unsafe path"},
		{"nested traversal", []testutil.Entry{{Path: "a/../../evil", Data: []byte("x")}}, "unsafe path"},
		{"inner dotdot", []testutil.Entry{{Path: "a/../b", Data: []byte("x")}}, "unsafe path"},
		{"absolute", []testutil.Entry{{Path: "/tmp/evil", Data: []byte("x")}}, "unsafe path"},
		{"backslash", []testutil.Entry{{Path: `a\..\evil`, Data: []byte("x")}}, "unsafe path"},
		{"long name", []testutil.Entry{{Path: strings.Repeat("a", MaxPathLen+1), Data: []byte("x")}}, "longer than"},
		{"symlink outside", []testutil.Entry{{Path: "A.app/link", Link: "../../outside"}}, "outside"},
		{"symlink absolute", []testutil.Entry{{Path: "A.app/link", Link: "/etc/passwd"}}, "absolute"},
		{"symlink dangling", []testutil.Entry{{Path: "A.app/link", Link: "missing"}}, "does not resolve"},
		{"write via symlink", []testutil.Entry{{Path: "A.app/sub/"}, {Path: "A.app/link", Link: "sub"}, {Path: "A.app/link/f", Data: []byte("x")}}, "through a symlink"},
		// d/s points to the root; d/e/t looks inside lexically but resolves
		// through s to in.zip, next to the root.
		{"chained escape", []testutil.Entry{{Path: "d/e/"}, {Path: "d/s", Link: ".."}, {Path: "d/e/t", Link: "../s/../in.zip"}}, "outside"},
		{"duplicate", []testutil.Entry{{Path: "a", Data: []byte("x")}, {Path: "a", Data: []byte("y")}}, "exists"},
		{"file over symlink", []testutil.Entry{{Path: "a/"}, {Path: "l", Link: "a"}, {Path: "l", Data: []byte("x")}}, "exists"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst, err := unzipEntries(t, c.entries, lim)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(dst), "evil")); err == nil {
				t.Fatal("file written outside")
			}
		})
	}
}

func TestUnzipLimits(t *testing.T) {
	many := make([]testutil.Entry, 11)
	for i := range many {
		many[i] = testutil.Entry{Path: "f" + string(rune('a'+i)), Data: []byte("x")}
	}
	cases := []struct {
		name    string
		entries []testutil.Entry
		lim     Limits
		want    string
	}{
		{"too many files", many, Limits{MaxExpandedBytes: 1 << 20, MaxFiles: 10}, "entries"},
		{"too many bytes", []testutil.Entry{{Path: "a", Data: make([]byte, 600)}, {Path: "b", Data: make([]byte, 600)}}, Limits{MaxExpandedBytes: 1000, MaxFiles: 10}, "expands"},
		{"at the limits", many[:10], Limits{MaxExpandedBytes: 10, MaxFiles: 10}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := unzipEntries(t, c.entries, c.lim)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

// TestUnzipLyingHeader: the declared size is small, the real data is big.
func TestUnzipLyingHeader(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.CreateRaw(&zip.FileHeader{Name: "a", Method: zip.Store, CompressedSize64: 2000, UncompressedSize64: 10, CRC32: 0})
	w.Write(make([]byte, 2000))
	zw.Close()
	src, dst := writeZip(t, buf.Bytes())
	if err := Unzip(src, dst, Limits{MaxExpandedBytes: 1000, MaxFiles: 10}); err == nil {
		t.Fatal("lying header accepted")
	}
}

// eocd returns a minimal end of central directory record.
func eocd(entries uint16, size, offset uint32) []byte {
	b := make([]byte, 22)
	binary.LittleEndian.PutUint32(b, eocdSig)
	binary.LittleEndian.PutUint16(b[8:], entries)
	binary.LittleEndian.PutUint16(b[10:], entries)
	binary.LittleEndian.PutUint32(b[12:], size)
	binary.LittleEndian.PutUint32(b[16:], offset)
	return b
}

func zip64Tail(entries, size uint64) []byte {
	rec := make([]byte, 56)
	binary.LittleEndian.PutUint32(rec, zip64EOCDSig)
	binary.LittleEndian.PutUint64(rec[24:], entries)
	binary.LittleEndian.PutUint64(rec[32:], entries)
	binary.LittleEndian.PutUint64(rec[40:], size)
	loc := make([]byte, 20)
	binary.LittleEndian.PutUint32(loc, zip64LocSig)
	binary.LittleEndian.PutUint64(loc[8:], 0) // record at offset 0
	return append(append(rec, loc...), eocd(0xffff, 0xffffffff, 0xffffffff)...)
}

// realZip returns a valid zip with n small entries.
func realZip(t *testing.T, n int, nameLen int) []byte {
	entries := make([]testutil.Entry, n)
	for i := range entries {
		entries[i] = testutil.Entry{Path: fmt.Sprintf("%0*d", nameLen, i), Data: []byte("x")}
	}
	return testutil.Zip(t, entries)
}

// forgeEnd rewrites the end record of a zip without a comment. When
// setDir is true, size and offset replace the directory size and offset.
func forgeEnd(b []byte, entries uint16, size, offset uint32, setDir bool) []byte {
	b = append([]byte(nil), b...)
	e := b[len(b)-eocdLen:]
	binary.LittleEndian.PutUint16(e[8:], entries)
	binary.LittleEndian.PutUint16(e[10:], entries)
	if setDir {
		if size != 0 {
			binary.LittleEndian.PutUint32(e[12:], size)
		}
		if offset != 0 {
			binary.LittleEndian.PutUint32(e[16:], offset)
		}
	}
	return b
}

func TestCentralDirCheck(t *testing.T) {
	twenty := realZip(t, 20, 4)
	cases := []struct {
		name     string
		data     []byte
		maxFiles int
		cdCap    uint64
		want     string
	}{
		{"valid", twenty, 100, 0, ""},
		{"exactly max files", twenty, 20, 0, ""},
		{"zip64 empty directory", zip64Tail(0, 0), 100, 0, ""},
		{"real count over limit", twenty, 10, 0, "more than 10 entries"},
		{"understated count", forgeEnd(twenty, 1, 0, 0, false), 100, 0, "declares 1 entries, central directory has 20"},
		{"overstated count", forgeEnd(twenty, 50, 0, 0, false), 100, 0, "declares 50"},
		{"central dir over cap", twenty, 100, 200, "larger than 200 bytes"},
		{"understated size", forgeEnd(twenty, 20, 1, 0, true), 100, 0, "before or inside"},
		{"offset past end", forgeEnd(twenty, 20, 0, 1<<30, true), 100, 0, "before or inside"},
		{"offset not at a record", forgeEnd(twenty, 20, 0, 3, true), 100, 0, "before or inside"},
		{"only an end record", eocd(5000, 100, 0), 100, 0, "before or inside"},
		{"zip64 size does not reach end record", zip64Tail(1<<40, 100), 100, 0, "before or inside"},
		{"zip64 bad record", append(make([]byte, 56), zip64Tail(1, 1)[56:]...), 100, 0, "zip64"},
		{"zip64 locator points after itself", zip64LocAfter(), 100, 0, "bad zip64 locator"},
		{"zero count, non-empty directory", forgeEnd(twenty, 0, 0, 0, false), 100, 0, "declares 0 entries"},
		{"not a zip", []byte("hello, this is not a zip archive at all"), 100, 0, "not a zip"},
		{"empty file", nil, 100, 0, "not a zip"},
		{"truncated record", append(append(le32(centralSig), make([]byte, 10)...), eocd(1, 14, 0)...), 100, 0, "truncated"},
		{"non-record bytes in directory", append(make([]byte, 46), eocd(1, 46, 0)...), 100, 0, "before or inside"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.cdCap != 0 {
				old := maxCentralDirBytes
				maxCentralDirBytes = c.cdCap
				defer func() { maxCentralDirBytes = old }()
			}
			src, _ := writeZip(t, c.data)
			err := checkCentralDir(src, c.maxFiles)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
	// Unzip runs the check first.
	src, dst := writeZip(t, twenty)
	if err := Unzip(src, dst, Limits{MaxExpandedBytes: 1 << 20, MaxFiles: 10}); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("Unzip: %v", err)
	}
}

// TestBaseOffsetExploit: the end record says offset 0 and 0 entries but
// keeps the real directory size. A walk from offset 0 sees a local header
// and counts nothing, while archive/zip computes a base offset and finds
// all 65536 records. The check must refuse it before archive/zip runs.
func TestBaseOffsetExploit(t *testing.T) {
	// Go writes ZIP64 end records at this size. Drop them and write a plain
	// end record: count 0 (65536 mod 65536), the real size, offset 0.
	z := realZip(t, 65536, 6)
	loc := z[len(z)-eocdLen-zip64LocLen:]
	recAt := binary.LittleEndian.Uint64(loc[8:])
	rec := z[recAt:]
	cdSize := binary.LittleEndian.Uint64(rec[40:])
	data := append(append([]byte(nil), z[:recAt]...), eocd(0, uint32(cdSize), 0)...)
	src, dst := writeZip(t, data)

	// Prove the forged file fools archive/zip on its own.
	zr, err := zip.OpenReader(src)
	if err != nil {
		t.Fatalf("fixture is not an exploit: archive/zip rejects it: %v", err)
	}
	n := len(zr.File)
	zr.Close()
	if n != 65536 {
		t.Fatalf("fixture is not an exploit: archive/zip sees %d files", n)
	}
	// The preflight alone rejects it; Unzip runs the preflight before
	// zip.OpenReader.
	if err := checkCentralDir(src, 1000); err == nil || !strings.Contains(err.Error(), "before or inside the central directory") {
		t.Fatalf("preflight: %v", err)
	}
	err = Unzip(src, dst, Limits{MaxExpandedBytes: 1 << 30, MaxFiles: 1000})
	if err == nil || !strings.Contains(err.Error(), "before or inside the central directory") {
		t.Fatalf("err = %v", err)
	}

	// Same records, honest offset: the count wrapped to 0 and is refused.
	cdOffset := binary.LittleEndian.Uint64(rec[48:])
	honest := append(append([]byte(nil), z[:recAt]...), eocd(0, uint32(cdSize), uint32(cdOffset))...)
	src2, _ := writeZip(t, honest)
	if err := checkCentralDir(src2, 1<<20); err == nil || !strings.Contains(err.Error(), "declares 0 entries") {
		t.Fatalf("wrapped count: %v", err)
	}
	if ents, _ := os.ReadDir(dst); len(ents) != 0 {
		t.Fatal("files were extracted")
	}
}

// zip64LocAfter returns ZIP64 end records whose locator points past itself.
func zip64LocAfter() []byte {
	b := zip64Tail(0, 0)
	binary.LittleEndian.PutUint64(b[56+8:], 60) // record "at" the locator
	return b
}

func le32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func TestUnzipDiskGuard(t *testing.T) {
	entries := []testutil.Entry{{Path: "a", Data: make([]byte, 3000)}, {Path: "b", Data: make([]byte, 3000)}}
	cases := []struct {
		name  string
		free  []uint64 // returned by successive calls; the last repeats
		fail  error
		want  string
		calls int
	}{
		// Each 3000-byte file is one write that crosses the 2000-byte interval.
		{"plenty of disk", []uint64{1 << 30}, nil, "", 2},
		{"disk fills during extraction", []uint64{1 << 30, 10}, nil, "free disk fell", 2},
		{"low from the start", []uint64{10}, nil, "free disk fell", 1},
		{"statfs error", nil, os.ErrPermission, "check free disk", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			calls := 0
			lim := Limits{MaxExpandedBytes: 1 << 20, MaxFiles: 10, MinFreeBytes: 100, CheckEvery: 2000,
				FreeBytes: func(string) (uint64, error) {
					calls++
					if c.fail != nil {
						return 0, c.fail
					}
					return c.free[min(calls-1, len(c.free)-1)], nil
				}}
			_, err := unzipEntries(t, entries, lim)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if calls != c.calls {
				t.Fatalf("FreeBytes calls = %d, want %d", calls, c.calls)
			}
		})
	}
}

func TestFindAppShape(t *testing.T) {
	cases := []struct {
		name    string
		entries []testutil.Entry
		ok      bool
	}{
		{"one app", []testutil.Entry{{Path: "A.app/x", Data: []byte("x")}}, true},
		{"one app plus ignored files", []testutil.Entry{{Path: "A.app/x", Data: []byte("x")}, {Path: ".DS_Store", Data: []byte("x")}, {Path: "__MACOSX/A.app/._x", Data: []byte("x")}}, true},
		{"two apps", []testutil.Entry{{Path: "A.app/x", Data: []byte("x")}, {Path: "B.app/x", Data: []byte("x")}}, false},
		{"extra file", []testutil.Entry{{Path: "A.app/x", Data: []byte("x")}, {Path: "README", Data: []byte("x")}}, false},
		{"no app", []testutil.Entry{{Path: "A/x", Data: []byte("x")}}, false},
		{"app is a file", []testutil.Entry{{Path: "A.app", Data: []byte("x")}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dst, err := unzipEntries(t, c.entries, lim)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := FindApp(dst); (err == nil) != c.ok {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestCheckFrameworks(t *testing.T) {
	fw := "A.app/Contents/Frameworks/F.framework/"
	cases := []struct {
		name    string
		entries []testutil.Entry
		lost    bool
	}{
		{"proper links", []testutil.Entry{{Path: fw + "Versions/A/F", Data: []byte("x")}, {Path: fw + "Versions/Current", Link: "A"}, {Path: fw + "F", Link: "Versions/Current/F"}}, false},
		{"shallow framework", []testutil.Entry{{Path: fw + "F", Data: []byte("x")}}, false},
		{"Current is a directory", []testutil.Entry{{Path: fw + "Versions/A/F", Data: []byte("x")}, {Path: fw + "Versions/Current/F", Data: []byte("x")}, {Path: fw + "F", Link: "Versions/A/F"}}, true},
		{"Current missing", []testutil.Entry{{Path: fw + "Versions/A/F", Data: []byte("x")}}, true},
		{"top-level binary copied", []testutil.Entry{{Path: fw + "Versions/A/F", Data: []byte("x")}, {Path: fw + "Versions/Current", Link: "A"}, {Path: fw + "F", Data: []byte("x")}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			testutil.WriteTree(t, dir, c.entries)
			err := CheckFrameworks(filepath.Join(dir, "A.app"))
			if c.lost != errors.Is(err, ErrLostSymlinks) || !c.lost && err != nil {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

// TestRealArchivers builds fixtures with the real ditto and zip tools, when
// installed, and checks how our extraction handles each.
func TestRealArchivers(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args func(src, dst string) []string
		dir  func(src string) string
		lost bool
	}{
		{"ditto keepParent", "ditto", func(src, dst string) []string { return []string{"-c", "-k", "--keepParent", src, dst} }, nil, false},
		{"zip -r -y", "zip", func(src, dst string) []string { return []string{"-q", "-r", "-y", dst, filepath.Base(src)} }, filepath.Dir, false},
		{"plain zip -r follows links", "zip", func(src, dst string) []string { return []string{"-q", "-r", dst, filepath.Base(src)} }, filepath.Dir, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := exec.LookPath(c.tool); err != nil {
				t.Skip(c.tool + " not installed")
			}
			dir := t.TempDir()
			testutil.WriteTree(t, dir, testutil.ElectronLikeApp("com.example.app"))
			src := filepath.Join(dir, "Example.app")
			zipPath := filepath.Join(t.TempDir(), "in.zip")
			cmd := exec.CommandContext(context.Background(), c.tool, c.args(src, zipPath)...)
			if c.dir != nil {
				cmd.Dir = c.dir(src)
			}
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s: %v %s", c.tool, err, out)
			}
			dst := filepath.Join(t.TempDir(), "out")
			os.Mkdir(dst, 0o700)
			if err := Unzip(zipPath, dst, Limits{MaxExpandedBytes: 1 << 24, MaxFiles: 1000}); err != nil {
				t.Fatal(err)
			}
			app, err := FindApp(dst)
			if err != nil {
				t.Fatal(err)
			}
			err = CheckFrameworks(app)
			if c.lost {
				if !errors.Is(err, ErrLostSymlinks) || !strings.Contains(err.Error(), "ditto -c -k --keepParent") {
					t.Fatalf("err = %v, want lost symlinks", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			cur := filepath.Join(app, "Contents/Frameworks/Electron Framework.framework/Versions/Current")
			if target, err := os.Readlink(cur); err != nil || target != "A" {
				t.Fatalf("Versions/Current: %q %v", target, err)
			}
			if fi, err := os.Stat(filepath.Join(app, "Contents/MacOS/Example")); err != nil || fi.Mode()&0o111 == 0 {
				t.Fatalf("exec bit: %v %v", fi, err)
			}
		})
	}
}

func TestSHA256File(t *testing.T) {
	p := filepath.Join(t.TempDir(), "f")
	os.WriteFile(p, []byte("abc"), 0o600)
	got, err := SHA256File(p)
	if err != nil || got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("%s %v", got, err)
	}
	if _, err := SHA256File(p + "x"); err == nil {
		t.Fatal("missing file")
	}
}

func TestZipAndCopyCommands(t *testing.T) {
	r := &testutil.FakeRunner{}
	dir := t.TempDir()
	testutil.WriteTree(t, dir, []testutil.Entry{{Path: "A.app/x", Data: []byte("x")}})
	if err := Zip(context.Background(), r, filepath.Join(dir, "A.app"), filepath.Join(dir, "o.zip")); err != nil {
		t.Fatal(err)
	}
	if err := Copy(context.Background(), r, filepath.Join(dir, "A.app"), filepath.Join(dir, "B.app")); err != nil {
		t.Fatal(err)
	}
	cmds := r.Commands()
	if !strings.HasPrefix(cmds[0], "ditto -c -k --keepParent ") || !strings.HasPrefix(cmds[1], "ditto ") {
		t.Fatalf("%q", cmds)
	}
}
