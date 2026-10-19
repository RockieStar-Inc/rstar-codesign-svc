// Package testutil has fakes and fixtures for tests. Only tests import it.
package testutil

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/runner"
)

// SubmissionID is the notary id the fake returns.
const SubmissionID = "2efe2717-52ef-43a5-96dc-0797e4ca1041"

// TeamID is the team the fake codesign reports.
const TeamID = "TEAMID1234"

// Mach-O fixtures: 64-bit little-endian headers with a file type.
var (
	MachOExec   = thinMachO(2)
	MachODylib  = thinMachO(6)
	MachOBundle = thinMachO(8)
	// MachO is kept as an alias for an executable.
	MachO = MachOExec
	// FatExec is a universal binary whose first slice is MH_EXECUTE.
	FatExec = fatMachO(MachOExec)
)

func thinMachO(fileType byte) []byte {
	return []byte{0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0x00, 0x00, 0x01, 0, 0, 0, 0, fileType, 0, 0, 0}
}

// fatMachO wraps one slice in a fat header with the slice at offset 4096.
func fatMachO(slice []byte) []byte {
	b := make([]byte, 4096+len(slice))
	copy(b, []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1})
	// fat_arch: cputype arm64, cpusubtype 0, offset 4096, size, align 14
	copy(b[8:], []byte{0x01, 0x00, 0x00, 0x0c, 0, 0, 0, 0, 0, 0, 0x10, 0, 0, 0, 0, byte(len(slice)), 0, 0, 0, 14})
	copy(b[4096:], slice)
	return b
}

// FakeRunner pretends to be codesign, plutil, ditto, hdiutil, xcrun, spctl
// and security. It records every command.
type FakeRunner struct {
	mu    sync.Mutex
	Calls []runner.Cmd

	// NotaryStatuses are returned by `notarytool info` in order; the last
	// one repeats. Default: Accepted.
	NotaryStatuses []string
	infoCalls      int
	// Fail makes a command fail when its joined argv contains the key.
	Fail map[string]string
	// Hook runs before the default behavior; return true to skip it.
	Hook func(c runner.Cmd) (runner.Result, error, bool)
}

var plistKeyRe = `<key>%s</key>\s*<string>([^<]*)</string>`

func (f *FakeRunner) Run(ctx context.Context, c runner.Cmd) (runner.Result, error) {
	f.mu.Lock()
	f.Calls = append(f.Calls, c)
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return runner.Result{}, err
	}
	if f.Hook != nil {
		if res, err, done := f.Hook(c); done {
			return res, err
		}
	}
	line := c.Name + " " + strings.Join(c.Args, " ")
	for k, msg := range f.Fail {
		if strings.Contains(line, k) {
			return runner.Result{Stderr: []byte(msg)}, fmt.Errorf("%s: exit status 1: %s", c.Name, msg)
		}
	}
	a := c.Args
	switch c.Name {
	case "plutil":
		// plutil -extract KEY raw -o - FILE
		b, err := os.ReadFile(a[len(a)-1])
		if err != nil {
			return runner.Result{}, err
		}
		m := regexp.MustCompile(fmt.Sprintf(plistKeyRe, regexp.QuoteMeta(a[1]))).FindSubmatch(b)
		if m == nil {
			return runner.Result{}, fmt.Errorf("plutil: no key %s", a[1])
		}
		return runner.Result{Stdout: append(m[1], '\n')}, nil
	case "codesign":
		if a[0] == "-d" {
			return runner.Result{Stderr: []byte("Executable=x\nTeamIdentifier=" + TeamID + "\n")}, nil
		}
		return runner.Result{}, nil
	case "ditto":
		if a[0] == "-c" {
			return runner.Result{}, ZipDir(a[len(a)-2], a[len(a)-1])
		}
		return runner.Result{}, os.MkdirAll(a[len(a)-1], 0o755)
	case "hdiutil":
		return runner.Result{}, os.WriteFile(a[len(a)-1], []byte("dmg"), 0o644)
	case "xcrun":
		if a[0] == "notarytool" {
			switch a[1] {
			case "submit":
				return runner.Result{Stdout: []byte(`{"id":"` + SubmissionID + `","message":"Successfully uploaded file"}`)}, nil
			case "info":
				f.mu.Lock()
				st := "Accepted"
				if n := len(f.NotaryStatuses); n > 0 {
					st = f.NotaryStatuses[min(f.infoCalls, n-1)]
				}
				f.infoCalls++
				f.mu.Unlock()
				return runner.Result{Stdout: []byte(`{"id":"` + a[2] + `","status":"` + st + `"}`)}, nil
			case "log":
				return runner.Result{Stdout: []byte(`{"status":"Invalid","statusSummary":"Archive contains critical validation errors","issues":[{"severity":"error","path":"Example.zip/Example.app/Contents/MacOS/Example","message":"The signature does not include a secure timestamp."}]}`)}, nil
			}
		}
		return runner.Result{}, nil
	}
	return runner.Result{}, nil
}

// ZipDir writes a zip of src with src's own name at the root, like
// `ditto -c -k --keepParent`. Symlinks are stored as links.
func ZipDir(src, dst string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	zw := zip.NewWriter(f)
	parent := filepath.Dir(src)
	err = filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(parent, p)
		info, err := d.Info()
		if err != nil {
			return err
		}
		h, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		h.Name = filepath.ToSlash(rel)
		var data []byte
		switch {
		case d.IsDir():
			h.Name += "/"
		case d.Type()&fs.ModeSymlink != 0:
			t, err := os.Readlink(p)
			if err != nil {
				return err
			}
			data = []byte(t)
		default:
			if data, err = os.ReadFile(p); err != nil {
				return err
			}
			h.Method = zip.Deflate
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		return err
	})
	if cerr := zw.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// Commands returns the recorded commands as joined strings.
func (f *FakeRunner) Commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.Calls))
	for i, c := range f.Calls {
		out[i] = c.Name + " " + strings.Join(c.Args, " ")
	}
	return out
}

// Plist returns a small XML Info.plist.
func Plist(id, exe string) string {
	return `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>` + id + `</string>
<key>CFBundleExecutable</key><string>` + exe + `</string>
</dict></plist>
`
}

// Entry is one file in a fixture tree. Link is a symlink target.
type Entry struct {
	Path string
	Data []byte
	Mode fs.FileMode
	Link string
}

// ElectronLikeApp returns a fake Electron-style app tree under "Example.app/":
// a framework with Versions/Current, a helper app, an XPC service, a bundled
// Node binary (fat MH_EXECUTE), a dylib, an MH_BUNDLE plugin, and a resource.
func ElectronLikeApp(topID string) []Entry {
	fw := "Example.app/Contents/Frameworks/Electron Framework.framework/"
	helper := "Example.app/Contents/Frameworks/Example Helper (Renderer).app/"
	xpc := "Example.app/Contents/XPCServices/Example Service.xpc/"
	return []Entry{
		{Path: "Example.app/Contents/Info.plist", Data: []byte(Plist(topID, "Example"))},
		{Path: "Example.app/Contents/MacOS/Example", Data: MachOExec, Mode: 0o755},
		{Path: "Example.app/Contents/Resources/app.asar", Data: []byte("asar")},
		{Path: "Example.app/Contents/Resources/node/bin/node", Data: FatExec, Mode: 0o755},
		{Path: "Example.app/Contents/Resources/native/addon.node", Data: MachOBundle, Mode: 0o644},
		{Path: xpc + "Contents/Info.plist", Data: []byte(Plist(topID+".service", "Example Service"))},
		{Path: xpc + "Contents/MacOS/Example Service", Data: MachOExec, Mode: 0o755},
		{Path: fw + "Versions/A/Electron Framework", Data: MachODylib, Mode: 0o755},
		{Path: fw + "Versions/A/Libraries/libffmpeg.dylib", Data: MachODylib, Mode: 0o644},
		{Path: fw + "Versions/A/Resources/Info.plist", Data: []byte(Plist("com.github.Electron.framework", "Electron Framework"))},
		{Path: fw + "Versions/Current", Link: "A"},
		{Path: fw + "Electron Framework", Link: "Versions/Current/Electron Framework"},
		{Path: fw + "Libraries", Link: "Versions/Current/Libraries"},
		{Path: helper + "Contents/Info.plist", Data: []byte(Plist(topID+".helper.renderer", "Example Helper (Renderer)"))},
		{Path: helper + "Contents/MacOS/Example Helper (Renderer)", Data: MachOExec, Mode: 0o755},
	}
}

// WriteTree writes entries under dir.
func WriteTree(t testing.TB, dir string, entries []Entry) {
	t.Helper()
	for _, e := range entries {
		p := filepath.Join(dir, filepath.FromSlash(e.Path))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if e.Link != "" {
			if err := os.Symlink(e.Link, p); err != nil {
				t.Fatal(err)
			}
			continue
		}
		mode := e.Mode
		if mode == 0 {
			mode = 0o644
		}
		if err := os.WriteFile(p, e.Data, mode); err != nil {
			t.Fatal(err)
		}
	}
}

// Zip builds a zip archive in memory. Symlinks are stored the way ditto and
// `zip -y` store them: mode bits plus the target as content.
func Zip(t testing.TB, entries []Entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.Path, Method: zip.Deflate}
		data := e.Data
		switch {
		case e.Link != "":
			h.SetMode(fs.ModeSymlink | 0o755)
			data = []byte(e.Link)
		case strings.HasSuffix(e.Path, "/"):
			h.SetMode(fs.ModeDir | 0o755)
			h.Method = zip.Store
		default:
			mode := e.Mode
			if mode == 0 {
				mode = 0o644
			}
			h.SetMode(mode)
		}
		w, err := zw.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
