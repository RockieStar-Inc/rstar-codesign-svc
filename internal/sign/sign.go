// Package sign signs an .app bundle from the inside out with codesign.
package sign

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/archive"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/runner"
)

var bundleExts = []string{".app", ".framework", ".xpc", ".appex"}

// appLike bundles have a Contents/MacOS main executable and may carry entitlements.
var appLike = []string{".app", ".xpc", ".appex"}

// Kinds of signable items.
const (
	KindApp        = "app-bundle" // .app, .xpc, .appex
	KindFramework  = "framework"
	KindExecutable = "executable" // MH_EXECUTE
	KindDylib      = "dylib"      // MH_DYLIB
	KindBundle     = "bundle"     // MH_BUNDLE (plugin)
	KindOther      = "macho-other"
)

// Item is one thing to pass to codesign.
type Item struct {
	Path         string
	Rel          string // relative to the .app, "." for the app itself
	Bundle       bool
	Kind         string
	Entitlements string
}

// Plan lists what to sign. Everything inside a bundle comes before the
// bundle; the main app is last. Symlinks are never followed or signed, but a
// symlink that leaves the bundle is an error. A bundle's own main executable
// is not signed alone: signing the bundle signs it.
func Plan(ctx context.Context, r runner.Runner, app string, prof config.Profile) ([]Item, error) {
	root, err := filepath.EvalSymlinks(app)
	if err != nil {
		return nil, err
	}
	var items []Item
	mains := map[string]bool{}
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			return archive.CheckSymlink(root, p)
		case d.IsDir():
			if d.Name() == "_CodeSignature" {
				return filepath.SkipDir
			}
			ext := filepath.Ext(d.Name())
			if !slices.Contains(bundleExts, ext) {
				return nil
			}
			main, err := mainExecutable(ctx, r, p, ext)
			if err != nil {
				return fmt.Errorf("%s: %w", rel, err)
			}
			mains[main] = true
			if p != root {
				kind := KindApp
				if ext == ".framework" {
					kind = KindFramework
				}
				items = append(items, Item{Path: p, Rel: rel, Bundle: true, Kind: kind})
			}
		case d.Type().IsRegular():
			kind, err := machOKind(p)
			if err != nil {
				return err
			}
			if kind != "" {
				items = append(items, Item{Path: p, Rel: rel, Kind: kind})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	// Bundles are visited before their contents, so drop main executables now.
	items = slices.DeleteFunc(items, func(it Item) bool { return !it.Bundle && mains[it.Path] })
	// A deeper path is never a parent of a shallower one, so deepest-first
	// puts every bundle after its contents.
	slices.SortStableFunc(items, func(a, b Item) int {
		if da, db := depth(a.Rel), depth(b.Rel); da != db {
			return db - da
		}
		return strings.Compare(a.Rel, b.Rel)
	})
	items = append(items, Item{Path: root, Rel: ".", Bundle: true, Kind: KindApp})
	for i := range items {
		items[i].Entitlements = entitlementsFor(prof, items[i])
	}
	return items, nil
}

// mainExecutable returns the path of the bundle's own binary.
func mainExecutable(ctx context.Context, r runner.Runner, bundle, ext string) (string, error) {
	if ext == ".framework" {
		// Versions/A/Name is the binary; Name and Versions/Current are symlinks.
		name := strings.TrimSuffix(filepath.Base(bundle), ext)
		if cur, err := os.Readlink(filepath.Join(bundle, "Versions", "Current")); err == nil {
			return filepath.Join(bundle, "Versions", cur, name), nil
		}
		return filepath.Join(bundle, name), nil
	}
	exe, err := PlistValue(ctx, r, filepath.Join(bundle, "Contents", "Info.plist"), "CFBundleExecutable")
	if err != nil {
		return "", err
	}
	if strings.Contains(exe, "/") {
		return "", fmt.Errorf("bad CFBundleExecutable %q", exe)
	}
	return filepath.Join(bundle, "Contents", "MacOS", exe), nil
}

func depth(rel string) int { return strings.Count(rel, "/") + 1 }

// entitlementsFor picks entitlements like electron-builder:
//   - the main app gets the profile's entitlements;
//   - nested .app/.xpc/.appex bundles and standalone MH_EXECUTE binaries get
//     the first matching override, else inherit_entitlements;
//   - frameworks, dylibs and MH_BUNDLE plugins never get entitlements.
func entitlementsFor(prof config.Profile, it Item) string {
	if it.Rel == "." {
		return prof.Entitlements
	}
	if it.Kind != KindApp && it.Kind != KindExecutable {
		return ""
	}
	for _, o := range prof.EntitlementOverrides {
		if ok, err := path.Match(o.Match, it.Rel); err == nil && ok {
			return o.Entitlements
		}
	}
	return prof.InheritEntitlements
}

// Mach-O file types.
const (
	mhExecute = 0x2
	mhDylib   = 0x6
	mhBundle  = 0x8
)

// machOKind returns the item kind of a Mach-O file, or "" when p is not
// Mach-O. For a fat binary it reads the first slice.
func machOKind(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	ft, ok := machOFileType(f, 0, 0)
	if !ok {
		return "", nil
	}
	switch ft {
	case mhExecute:
		return KindExecutable, nil
	case mhDylib:
		return KindDylib, nil
	case mhBundle:
		return KindBundle, nil
	}
	return KindOther, nil
}

func machOFileType(r io.ReaderAt, off int64, depth int) (uint32, bool) {
	var hdr [16]byte
	if _, err := r.ReadAt(hdr[:], off); err != nil {
		return 0, false
	}
	switch binary.BigEndian.Uint32(hdr[:4]) {
	case 0xfeedface, 0xfeedfacf:
		return binary.BigEndian.Uint32(hdr[12:]), true
	case 0xcefaedfe, 0xcffaedfe:
		return binary.LittleEndian.Uint32(hdr[12:]), true
	case 0xcafebabe, 0xcafebabf:
		// Java class files share 0xcafebabe; their next word is a version >= 45.
		n := binary.BigEndian.Uint32(hdr[4:8])
		if depth > 0 || n == 0 || n >= 45 {
			return 0, false
		}
		var sliceOff int64
		if binary.BigEndian.Uint32(hdr[:4]) == 0xcafebabe {
			var a [20]byte // fat_arch: cputype, cpusubtype, offset, size, align
			if _, err := r.ReadAt(a[:], off+8); err != nil {
				return 0, false
			}
			sliceOff = int64(binary.BigEndian.Uint32(a[8:12]))
		} else {
			var a [32]byte // fat_arch_64: cputype, cpusubtype, offset(8), size(8), align, reserved
			if _, err := r.ReadAt(a[:], off+8); err != nil {
				return 0, false
			}
			sliceOff = int64(binary.BigEndian.Uint64(a[8:16]))
		}
		if sliceOff <= 0 {
			return 0, false
		}
		return machOFileType(r, sliceOff, depth+1)
	}
	return 0, false
}

// ReportItem describes one signed item for the job status.
type ReportItem struct {
	Path         string `json:"path"`
	Type         string `json:"type"`
	Entitlements string `json:"entitlements,omitempty"` // file name only
	Warning      string `json:"warning,omitempty"`
}

// Report lists what will be signed and flags executables that get the
// hardened runtime without entitlements: JIT runtimes (Node, V8) crash then.
func Report(prof config.Profile, items []Item) []ReportItem {
	out := make([]ReportItem, 0, len(items))
	for _, it := range items {
		ri := ReportItem{Path: it.Rel, Type: it.Kind}
		if it.Entitlements != "" {
			ri.Entitlements = filepath.Base(it.Entitlements)
		}
		if it.Kind == KindExecutable && prof.Runtime() && it.Entitlements == "" {
			ri.Warning = "hardened runtime without entitlements; JIT runtimes such as Node need com.apple.security.cs.allow-jit (set inherit_entitlements)"
		}
		out = append(out, ri)
	}
	return out
}

// Args builds the codesign arguments for one item.
func Args(prof config.Profile, it Item) []string {
	args := []string{"--force", "--timestamp"}
	if prof.Runtime() {
		args = append(args, "--options", "runtime")
	}
	args = append(args, "--sign", prof.Identity, "--keychain", prof.Keychain)
	if it.Entitlements != "" {
		args = append(args, "--entitlements", it.Entitlements)
	}
	return append(args, it.Path)
}

// Sign signs every item in order.
func Sign(ctx context.Context, r runner.Runner, prof config.Profile, items []Item) error {
	for _, it := range items {
		if _, err := r.Run(ctx, runner.Cmd{Name: "codesign", Args: Args(prof, it), Timeout: runner.CodesignTimeout}); err != nil {
			return fmt.Errorf("sign %s: %w", it.Rel, err)
		}
	}
	return nil
}

// Verify runs a strict deep verify and checks the team id.
func Verify(ctx context.Context, r runner.Runner, p, teamID string) error {
	if _, err := r.Run(ctx, runner.Cmd{Name: "codesign", Args: []string{"--verify", "--deep", "--strict", "--verbose=2", p}, Timeout: runner.CodesignTimeout}); err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	return CheckTeam(ctx, r, p, teamID)
}

var teamRe = regexp.MustCompile(`(?m)^TeamIdentifier=(\S+)`)

// CheckTeam reads the signature's team id and compares it.
func CheckTeam(ctx context.Context, r runner.Runner, p, teamID string) error {
	res, err := r.Run(ctx, runner.Cmd{Name: "codesign", Args: []string{"-d", "--verbose=2", p}, Timeout: runner.CodesignTimeout})
	if err != nil {
		return fmt.Errorf("read signature: %w", err)
	}
	m := teamRe.FindSubmatch(append(res.Stderr, res.Stdout...))
	if m == nil {
		return fmt.Errorf("no TeamIdentifier in signature of %s", filepath.Base(p))
	}
	if got := string(m[1]); got != teamID {
		return fmt.Errorf("team id is %s, want %s", got, teamID)
	}
	return nil
}

// PlistValue reads one string key from a plist with plutil.
func PlistValue(ctx context.Context, r runner.Runner, plist, key string) (string, error) {
	res, err := r.Run(ctx, runner.Cmd{Name: "plutil", Args: []string{"-extract", key, "raw", "-o", "-", plist}, Timeout: runner.ShortTimeout})
	if err != nil {
		return "", fmt.Errorf("read %s: %w", key, err)
	}
	v := string(bytes.TrimSpace(res.Stdout))
	if v == "" {
		return "", fmt.Errorf("empty %s", key)
	}
	return v, nil
}

// BundleID reads CFBundleIdentifier from the app's Info.plist.
func BundleID(ctx context.Context, r runner.Runner, app string) (string, error) {
	return PlistValue(ctx, r, filepath.Join(app, "Contents", "Info.plist"), "CFBundleIdentifier")
}

// CheckNestedIDs makes sure every nested .app/.xpc/.appex has a bundle id
// equal to topID or starting with topID + ".".
func CheckNestedIDs(ctx context.Context, r runner.Runner, items []Item, topID string) error {
	for _, it := range items {
		if !it.Bundle || it.Rel == "." || !slices.Contains(appLike, filepath.Ext(it.Path)) {
			continue
		}
		id, err := BundleID(ctx, r, it.Path)
		if err != nil {
			return fmt.Errorf("%s: %w", it.Rel, err)
		}
		if id != topID && !strings.HasPrefix(id, topID+".") {
			return fmt.Errorf("nested bundle %s has id %s, which is not under %s", it.Rel, id, topID)
		}
	}
	return nil
}

// BundleIDAllowed reports whether id matches the profile list (globs allowed).
// An empty list allows any id.
func BundleIDAllowed(prof config.Profile, id string) bool {
	if len(prof.AllowedBundleIDs) == 0 {
		return true
	}
	for _, g := range prof.AllowedBundleIDs {
		if ok, err := path.Match(g, id); err == nil && ok {
			return true
		}
	}
	return false
}

// SignFile signs a flat file such as a DMG.
func SignFile(ctx context.Context, r runner.Runner, prof config.Profile, p string) error {
	_, err := r.Run(ctx, runner.Cmd{Name: "codesign", Args: []string{"--force", "--timestamp", "--sign", prof.Identity, "--keychain", prof.Keychain, p}, Timeout: runner.CodesignTimeout})
	return err
}

// UnlockKeychain unlocks kc with the password in pwFile. The password goes
// to `security -i` on stdin, never into argv or logs. Then it checks that the
// keychain is really unlocked, because `security -i` can exit 0 on errors.
func UnlockKeychain(ctx context.Context, r runner.Runner, kc, pwFile string) error {
	b, err := os.ReadFile(pwFile)
	if err != nil {
		return fmt.Errorf("read keychain password file: %w", err)
	}
	pw := strings.TrimRight(string(b), "\r\n")
	if pw == "" || strings.ContainsAny(pw, "\"\\\r\n") {
		return errors.New("keychain password must be one line without \" or \\")
	}
	line := fmt.Sprintf("unlock-keychain -p \"%s\" \"%s\"\n", pw, kc)
	if _, err := r.Run(ctx, runner.Cmd{Name: "security", Args: []string{"-i"}, Stdin: []byte(line), Timeout: runner.ShortTimeout, Secret: true}); err != nil {
		return fmt.Errorf("unlock keychain: %w", err)
	}
	if _, err := r.Run(ctx, runner.Cmd{Name: "security", Args: []string{"show-keychain-info", kc}, Timeout: runner.ShortTimeout}); err != nil {
		return fmt.Errorf("keychain is still locked: %w", err)
	}
	return nil
}
