// Package archive unpacks uploads safely and packs signed results.
//
// Unpacking uses Go's archive/zip, not ditto. Go lets us check every entry
// (path, size, count, symlink target) before anything touches the disk, and
// the checks run in tests without macOS tools. Extended attributes and
// AppleDouble files are dropped, which codesign wants anyway ("resource fork,
// Finder information, or similar detritus not allowed"). Packing uses
// `ditto -c -k --keepParent`, which keeps signatures intact.
package archive

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/runner"
)

// Limits bound the unpacked size of an upload.
type Limits struct {
	MaxExpandedBytes int64
	MaxFiles         int
	// When FreeBytes is set, extraction checks real free disk every
	// CheckEvery bytes written (default 256 MiB) and stops below MinFreeBytes.
	FreeBytes    func(dir string) (uint64, error)
	MinFreeBytes int64
	CheckEvery   int64
}

// diskGuard counts written bytes and checks free disk at intervals.
type diskGuard struct {
	lim     Limits
	dir     string
	written int64
	next    int64
}

func (g *diskGuard) add(n int64) error {
	g.written += n
	if g.lim.FreeBytes == nil || g.written < g.next {
		return nil
	}
	every := g.lim.CheckEvery
	if every <= 0 {
		every = 256 << 20
	}
	g.next = g.written + every
	free, err := g.lim.FreeBytes(g.dir)
	if err != nil {
		return fmt.Errorf("check free disk: %w", err)
	}
	if int64(min(free, 1<<62)) < g.lim.MinFreeBytes {
		return fmt.Errorf("free disk fell below %d bytes during extraction", g.lim.MinFreeBytes)
	}
	return nil
}

type guardWriter struct {
	w io.Writer
	g *diskGuard
}

func (gw guardWriter) Write(p []byte) (int, error) {
	n, err := gw.w.Write(p)
	if gerr := gw.g.add(int64(n)); err == nil {
		err = gerr
	}
	return n, err
}

// Unzip extracts src into dst (which must exist and be empty). It rejects
// absolute paths, path traversal, symlinks that leave dst, writes through
// symlinks, and archives over the limits.
func Unzip(src, dst string, lim Limits) error {
	if err := checkCentralDir(src, lim.MaxFiles); err != nil {
		return err
	}
	zr, err := zip.OpenReader(src)
	if err != nil {
		return fmt.Errorf("open zip: %w", err)
	}
	defer zr.Close()

	root, err := filepath.EvalSymlinks(dst)
	if err != nil {
		return err
	}
	if len(zr.File) > lim.MaxFiles {
		return fmt.Errorf("zip has %d entries, limit is %d", len(zr.File), lim.MaxFiles)
	}
	// Pre-scan the central directory: names and declared sizes.
	var declared uint64
	var entries []*zip.File
	for _, f := range zr.File {
		name := f.Name
		if skipEntry(name) {
			continue
		}
		if err := checkName(name); err != nil {
			return err
		}
		declared += f.UncompressedSize64
		if declared > uint64(lim.MaxExpandedBytes) {
			return fmt.Errorf("zip expands to more than %d bytes", lim.MaxExpandedBytes)
		}
		entries = append(entries, f)
	}

	var written int64
	var links []string
	guard := &diskGuard{lim: lim, dir: root, next: lim.CheckEvery}
	for i, f := range entries {
		if i >= lim.MaxFiles {
			return fmt.Errorf("zip has more than %d entries", lim.MaxFiles)
		}
		target := filepath.Join(root, filepath.FromSlash(strings.TrimSuffix(f.Name, "/")))
		if err := checkParents(root, target); err != nil {
			return err
		}
		mode := f.Mode()
		switch {
		case mode.IsDir():
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case mode&fs.ModeSymlink != 0:
			if err := extractSymlink(root, f, target); err != nil {
				return err
			}
			links = append(links, target)
		case mode.IsRegular():
			n, err := extractFile(f, target, lim.MaxExpandedBytes-written, guard)
			if err != nil {
				return err
			}
			written += n
		default:
			return fmt.Errorf("%s: unsupported file type %s", f.Name, mode.Type())
		}
	}
	// A link can be lexically inside root but escape through another link.
	for _, l := range links {
		if err := CheckSymlink(root, l); err != nil {
			return err
		}
	}
	return nil
}

func skipEntry(name string) bool {
	if strings.HasPrefix(name, "__MACOSX/") {
		return true
	}
	base := filepath.Base(strings.TrimSuffix(name, "/"))
	return strings.HasPrefix(base, "._") || base == ".DS_Store"
}

// MaxPathLen is the longest entry name accepted, in bytes.
const MaxPathLen = 1024

func checkName(name string) error {
	if len(name) > MaxPathLen {
		return fmt.Errorf("zip entry name longer than %d bytes", MaxPathLen)
	}
	n := strings.TrimSuffix(name, "/")
	if n == "" || strings.HasPrefix(name, "/") || strings.Contains(name, `\`) || !filepath.IsLocal(filepath.FromSlash(n)) {
		return fmt.Errorf("unsafe path in zip: %q", name)
	}
	for _, part := range strings.Split(n, "/") {
		if part == ".." {
			return fmt.Errorf("unsafe path in zip: %q", name)
		}
	}
	return nil
}

// checkParents makes sure no existing parent of target is a symlink, so a
// file cannot be written through a link.
func checkParents(root, target string) error {
	rel, err := filepath.Rel(root, filepath.Dir(target))
	if err != nil || rel == "." {
		return err
	}
	cur := root
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("zip entry %s goes through a symlink", target)
		}
	}
	return nil
}

func extractSymlink(root string, f *zip.File, target string) error {
	if f.UncompressedSize64 > 4096 {
		return fmt.Errorf("%s: symlink target too long", f.Name)
	}
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, 4097))
	if err != nil {
		return err
	}
	dest := string(b)
	if filepath.IsAbs(dest) {
		return fmt.Errorf("%s: symlink to absolute path %q", f.Name, dest)
	}
	if !within(root, filepath.Join(filepath.Dir(target), dest)) {
		return fmt.Errorf("%s: symlink points outside the archive: %q", f.Name, dest)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	return os.Symlink(dest, target)
}

func extractFile(f *zip.File, target string, budget int64, guard *diskGuard) (int64, error) {
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return 0, err
	}
	perm := f.Mode().Perm() &^ 0o022
	if perm == 0 {
		perm = 0o644
	}
	perm |= 0o600
	out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, perm)
	if err != nil {
		return 0, err
	}
	rc, err := f.Open()
	if err != nil {
		out.Close()
		return 0, err
	}
	defer rc.Close()
	// The declared size can lie; count real bytes too.
	n, err := io.Copy(guardWriter{out, guard}, io.LimitReader(rc, budget+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return n, err
	}
	if n > budget {
		return n, errors.New("zip expands beyond the size limit")
	}
	return n, nil
}

// CheckSymlink returns an error when the symlink at link resolves outside root.
// Dangling links are rejected too. root must have no symlinks in its own path.
func CheckSymlink(root, link string) error {
	dest, err := os.Readlink(link)
	if err != nil {
		return err
	}
	if filepath.IsAbs(dest) {
		return fmt.Errorf("symlink %s points to absolute path %q", rel(root, link), dest)
	}
	real, err := filepath.EvalSymlinks(link)
	if err != nil {
		return fmt.Errorf("symlink %s does not resolve: %w", rel(root, link), err)
	}
	if !within(root, real) {
		return fmt.Errorf("symlink %s points outside the bundle", rel(root, link))
	}
	return nil
}

func within(root, p string) bool {
	r, err := filepath.Rel(root, filepath.Clean(p))
	return err == nil && filepath.IsLocal(r)
}

func rel(root, p string) string {
	if r, err := filepath.Rel(root, p); err == nil {
		return r
	}
	return p
}

// FindApp returns the .app in root. The root must hold exactly one .app
// directory and nothing else (__MACOSX and .DS_Store are skipped on unzip).
func FindApp(root string) (string, error) {
	ents, err := os.ReadDir(root)
	if err != nil {
		return "", err
	}
	if len(ents) != 1 || !ents[0].IsDir() || !strings.HasSuffix(ents[0].Name(), ".app") {
		names := make([]string, 0, len(ents))
		for _, e := range ents {
			names = append(names, e.Name())
		}
		return "", fmt.Errorf("zip root must hold exactly one .app and nothing else, found %q", names)
	}
	return filepath.Join(root, ents[0].Name()), nil
}

// ErrLostSymlinks means the archive was made by a tool that followed
// symlinks (plain `zip -r`), so framework bundles are broken.
var ErrLostSymlinks = errors.New("archive lost symlinks; create it with ditto -c -k --keepParent")

// CheckFrameworks fails when a versioned .framework has no Versions/Current
// symlink, or its top-level entries are real files instead of symlinks.
func CheckFrameworks(app string) error {
	return filepath.WalkDir(app, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || filepath.Ext(p) != ".framework" {
			return nil
		}
		versions := filepath.Join(p, "Versions")
		if fi, err := os.Lstat(versions); err != nil || !fi.IsDir() {
			return nil // shallow framework
		}
		rel, _ := filepath.Rel(app, p)
		cur, err := os.Lstat(filepath.Join(versions, "Current"))
		if err != nil || cur.Mode()&fs.ModeSymlink == 0 {
			return fmt.Errorf("%s: no Versions/Current symlink: %w", rel, ErrLostSymlinks)
		}
		ents, err := os.ReadDir(p)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if e.Name() != "Versions" && e.Type()&fs.ModeSymlink == 0 {
				return fmt.Errorf("%s/%s is not a symlink: %w", rel, e.Name(), ErrLostSymlinks)
			}
		}
		return filepath.SkipDir
	})
}

// Zip packs src (an .app or other bundle) into dst with ditto.
func Zip(ctx context.Context, r runner.Runner, src, dst string) error {
	_, err := r.Run(ctx, runner.Cmd{Name: "ditto", Args: []string{"-c", "-k", "--keepParent", src, dst}, Timeout: runner.DittoTimeout})
	return err
}

// Copy copies a bundle with ditto, keeping signatures and symlinks.
func Copy(ctx context.Context, r runner.Runner, src, dst string) error {
	_, err := r.Run(ctx, runner.Cmd{Name: "ditto", Args: []string{src, dst}, Timeout: runner.DittoTimeout})
	return err
}

// SHA256File returns the hex SHA-256 of a file.
func SHA256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
