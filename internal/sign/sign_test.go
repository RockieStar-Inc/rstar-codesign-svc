package sign

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/runner"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/testutil"
)

const (
	helperRel = "Contents/Frameworks/Example Helper (Renderer).app"
	xpcRel    = "Contents/XPCServices/Example Service.xpc"
	fwRel     = "Contents/Frameworks/Electron Framework.framework"
	dylibRel  = fwRel + "/Versions/A/Libraries/libffmpeg.dylib"
	nodeRel   = "Contents/Resources/node/bin/node"
	addonRel  = "Contents/Resources/native/addon.node"
)

var prof = config.Profile{
	Name: "release", Identity: "Developer ID Application: Example Corp (TEAMID1234)",
	Keychain: "/tmp/signing.keychain-db", TeamID: "TEAMID1234",
	Entitlements:        "/etc/ent/main.plist",
	InheritEntitlements: "/etc/ent/inherit.plist",
	EntitlementOverrides: []config.Override{
		{Match: "Contents/Frameworks/*Helper (Renderer).app", Entitlements: "/etc/ent/renderer.plist"},
		// Must never apply: dylibs and frameworks get no entitlements.
		{Match: "Contents/Frameworks/*/Versions/A/Libraries/*.dylib", Entitlements: "/etc/ent/bad.plist"},
		{Match: "Contents/Frameworks/*.framework", Entitlements: "/etc/ent/bad.plist"},
	},
}

func appTree(t *testing.T, topID string) string {
	dir := t.TempDir()
	testutil.WriteTree(t, dir, testutil.ElectronLikeApp(topID))
	return filepath.Join(dir, "Example.app")
}

func TestPlanOrder(t *testing.T) {
	app := appTree(t, "com.example.app")
	items, err := Plan(context.Background(), &testutil.FakeRunner{}, app, prof)
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, it := range items {
		rels = append(rels, it.Rel)
	}
	// Symlinks (Versions/Current, top-level framework links) and bundle main
	// executables are absent; deepest first; main app last.
	want := []string{dylibRel, nodeRel, addonRel, fwRel, helperRel, xpcRel, "."}
	if !slices.Equal(rels, want) {
		t.Fatalf("order:\n got %q\nwant %q", rels, want)
	}
	for i, a := range items {
		for j, b := range items {
			inside := b.Rel == "." && a.Rel != "." || strings.HasPrefix(a.Rel, b.Rel+"/")
			if b.Bundle && inside && i > j {
				t.Fatalf("%s signed after its container %s", a.Rel, b.Rel)
			}
		}
	}
	got := map[string][2]string{}
	for _, it := range items {
		got[it.Rel] = [2]string{it.Kind, it.Entitlements}
	}
	wantEnt := map[string][2]string{
		".":       {KindApp, "/etc/ent/main.plist"},
		helperRel: {KindApp, "/etc/ent/renderer.plist"},
		xpcRel:    {KindApp, "/etc/ent/inherit.plist"},
		nodeRel:   {KindExecutable, "/etc/ent/inherit.plist"},
		fwRel:     {KindFramework, ""},
		dylibRel:  {KindDylib, ""},
		addonRel:  {KindBundle, ""},
	}
	for rel, w := range wantEnt {
		if got[rel] != w {
			t.Errorf("%s: got %v, want %v", rel, got[rel], w)
		}
	}
	for _, it := range items {
		args := strings.Join(Args(prof, it), " ")
		if strings.Contains(args, "--deep") || !strings.Contains(args, "--options runtime") || !strings.Contains(args, "--timestamp") {
			t.Fatalf("args: %s", args)
		}
		if (it.Kind == KindDylib || it.Kind == KindFramework) && strings.Contains(args, "--entitlements") {
			t.Fatalf("%s signed with entitlements", it.Rel)
		}
	}
}

func TestEntitlementSelection(t *testing.T) {
	over := []config.Override{
		{Match: "Contents/Resources/node/bin/node", Entitlements: "node.plist"},
		{Match: "Contents/Frameworks/*.app", Entitlements: "helper.plist"},
		{Match: "Contents/Frameworks/*.app", Entitlements: "second.plist"},
		{Match: "Contents/*", Entitlements: "broad.plist"},
		{Match: ".", Entitlements: "main-override.plist"},
	}
	full := config.Profile{Entitlements: "main.plist", InheritEntitlements: "inherit.plist", EntitlementOverrides: over}
	noInherit := config.Profile{Entitlements: "main.plist"}
	cases := []struct {
		name string
		prof config.Profile
		item Item
		want string
	}{
		{"main app keeps entitlements", full, Item{Rel: ".", Kind: KindApp, Bundle: true}, "main.plist"},
		{"helper app override, first match wins", full, Item{Rel: "Contents/Frameworks/H.app", Kind: KindApp, Bundle: true}, "helper.plist"},
		{"xpc inherits", full, Item{Rel: "Contents/XPCServices/S.xpc", Kind: KindApp, Bundle: true}, "inherit.plist"},
		{"appex inherits", full, Item{Rel: "Contents/PlugIns/E.appex", Kind: KindApp, Bundle: true}, "inherit.plist"},
		{"executable override", full, Item{Rel: "Contents/Resources/node/bin/node", Kind: KindExecutable}, "node.plist"},
		{"executable inherits", full, Item{Rel: "Contents/Resources/bin/tool", Kind: KindExecutable}, "inherit.plist"},
		{"executable glob override", full, Item{Rel: "Contents/tool", Kind: KindExecutable}, "broad.plist"},
		{"dylib never", full, Item{Rel: "Contents/libx.dylib", Kind: KindDylib}, ""},
		{"framework never", full, Item{Rel: "Contents/F.framework", Kind: KindFramework, Bundle: true}, ""},
		{"mh_bundle never", full, Item{Rel: "Contents/a.node", Kind: KindBundle}, ""},
		{"other macho never", full, Item{Rel: "Contents/o", Kind: KindOther}, ""},
		{"no inherit set", noInherit, Item{Rel: "Contents/Frameworks/H.app", Kind: KindApp, Bundle: true}, ""},
		{"no inherit executable", noInherit, Item{Rel: "Contents/tool", Kind: KindExecutable}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := entitlementsFor(c.prof, c.item); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func be32(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }

func TestMachOKind(t *testing.T) {
	fat64 := make([]byte, 8192+16)
	copy(fat64, append(be32(0xcafebabf), be32(1)...))
	binary.BigEndian.PutUint64(fat64[16:], 8192) // fat_arch_64.offset
	copy(fat64[8192:], testutil.MachOExec)
	beExec := append(append(append(be32(0xfeedfacf), be32(7)...), be32(3)...), be32(2)...)
	fatZero := []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1}
	fatZero = append(fatZero, make([]byte, 20)...)
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"thin executable", testutil.MachOExec, KindExecutable},
		{"thin dylib", testutil.MachODylib, KindDylib},
		{"thin bundle", testutil.MachOBundle, KindBundle},
		{"thin object", []byte{0xcf, 0xfa, 0xed, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0}, KindOther},
		{"big-endian executable", beExec, KindExecutable},
		{"fat executable", testutil.FatExec, KindExecutable},
		{"fat64 executable", fat64, KindExecutable},
		{"fat dylib", fatDylib(), KindDylib},
		{"java class", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 0, 0, 0, 0, 0, 0, 0}, ""},
		{"fat with zero offset", fatZero, ""},
		{"fat truncated", []byte{0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}, ""},
		{"shell script", []byte("#!/bin/sh\necho hello world\n"), ""},
		{"short", []byte{0xcf, 0xfa}, ""},
		{"empty", nil, ""},
	}
	dir := t.TempDir()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(dir, strings.ReplaceAll(c.name, " ", "_"))
			os.WriteFile(p, c.data, 0o644)
			got, err := machOKind(p)
			if err != nil || got != c.want {
				t.Fatalf("got %q %v, want %q", got, err, c.want)
			}
		})
	}
	if _, err := machOKind(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing file: no error")
	}
}

func fatDylib() []byte {
	b := append([]byte(nil), testutil.FatExec...)
	copy(b[4096:], testutil.MachODylib)
	return b
}

func TestReport(t *testing.T) {
	off := false
	noRuntime := prof
	noRuntime.HardenedRuntime = &off
	items := []Item{
		{Rel: nodeRel, Kind: KindExecutable},
		{Rel: dylibRel, Kind: KindDylib},
		{Rel: ".", Kind: KindApp, Entitlements: "/etc/ent/main.plist"},
	}
	cases := []struct {
		name string
		prof config.Profile
		warn bool
	}{
		{"runtime, no entitlements: warn", prof, true},
		{"runtime off: no warning", noRuntime, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := Report(c.prof, items)
			if (r[0].Warning != "") != c.warn {
				t.Fatalf("executable warning = %q", r[0].Warning)
			}
			if r[1].Warning != "" {
				t.Fatal("dylib warned")
			}
			if r[2].Entitlements != "main.plist" || r[2].Type != KindApp {
				t.Fatalf("main: %+v", r[2])
			}
		})
	}
}

func TestPlanRejectsOutsideSymlink(t *testing.T) {
	for name, target := range map[string]string{"relative escape": "../../../outside", "absolute": "/etc/passwd"} {
		t.Run(name, func(t *testing.T) {
			app := appTree(t, "com.example.app")
			if err := os.Symlink(target, filepath.Join(app, "Contents/Resources/escape")); err != nil {
				t.Fatal(err)
			}
			if _, err := Plan(context.Background(), &testutil.FakeRunner{}, app, prof); err == nil {
				t.Fatal("outside symlink accepted")
			}
		})
	}
}

func TestPlanBadBundleExecutable(t *testing.T) {
	app := appTree(t, "com.example.app")
	os.WriteFile(filepath.Join(app, "Contents/Info.plist"), []byte(testutil.Plist("com.example.app", "../evil")), 0o644)
	if _, err := Plan(context.Background(), &testutil.FakeRunner{}, app, prof); err == nil {
		t.Fatal("CFBundleExecutable with / accepted")
	}
}

func TestCheckNestedIDs(t *testing.T) {
	ctx := context.Background()
	r := &testutil.FakeRunner{}
	app := appTree(t, "com.example.app")
	items, err := Plan(ctx, r, app, prof)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		top  string
		ok   bool
		name string
	}{
		{"com.example.app", true, "children under top id"},
		{"com.example.ap", false, "prefix without dot"},
		{"com.other", false, "foreign"},
		{"com.example.app.helper", false, "sibling ids not under a deeper top"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := CheckNestedIDs(ctx, r, items, c.top); (err == nil) != c.ok {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestBundleIDAllowed(t *testing.T) {
	p := config.Profile{AllowedBundleIDs: []string{"com.example.app", "com.example.beta.*"}}
	cases := []struct {
		id   string
		prof config.Profile
		want bool
	}{
		{"com.example.app", p, true},
		{"com.example.beta.x", p, true},
		{"com.evil", p, false},
		{"com.example.appx", p, false},
		{"anything", config.Profile{}, true},
	}
	for _, c := range cases {
		if got := BundleIDAllowed(c.prof, c.id); got != c.want {
			t.Errorf("%s: %v", c.id, got)
		}
	}
}

func TestVerifyAndTeam(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		r    *testutil.FakeRunner
		team string
		want string
	}{
		{"ok", &testutil.FakeRunner{}, testutil.TeamID, ""},
		{"wrong team", &testutil.FakeRunner{}, "OTHERTEAM1", "team id is"},
		{"verify fails", &testutil.FakeRunner{Fail: map[string]string{"--verify": "invalid signature"}}, testutil.TeamID, "verify"},
		{"no team in output", &testutil.FakeRunner{Hook: func(c runner.Cmd) (runner.Result, error, bool) {
			return runner.Result{Stderr: []byte("Executable=x\n")}, nil, c.Args[0] == "-d"
		}}, testutil.TeamID, "no TeamIdentifier"},
		{"display fails", &testutil.FakeRunner{Fail: map[string]string{"codesign -d": "boom"}}, testutil.TeamID, "read signature"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := Verify(ctx, c.r, "/x/Example.app", c.team)
			if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
		})
	}
}

func TestSignStopsOnError(t *testing.T) {
	r := &testutil.FakeRunner{Fail: map[string]string{"libffmpeg": "boom"}}
	items := []Item{{Path: "/a/libffmpeg.dylib", Rel: "libffmpeg.dylib"}, {Path: "/a", Rel: "."}}
	if err := Sign(context.Background(), r, prof, items); err == nil || !strings.Contains(err.Error(), "libffmpeg") {
		t.Fatalf("err = %v", err)
	}
	if len(r.Calls) != 1 {
		t.Fatal("continued after a failure")
	}
	if err := SignFile(context.Background(), &testutil.FakeRunner{}, prof, "/a.dmg"); err != nil {
		t.Fatal(err)
	}
}

func TestBundleIDErrors(t *testing.T) {
	ctx := context.Background()
	empty := &testutil.FakeRunner{Hook: func(c runner.Cmd) (runner.Result, error, bool) { return runner.Result{Stdout: []byte("\n")}, nil, true }}
	if _, err := BundleID(ctx, empty, "/x.app"); err == nil {
		t.Fatal("empty id accepted")
	}
	if _, err := BundleID(ctx, &testutil.FakeRunner{}, "/missing.app"); err == nil {
		t.Fatal("missing plist accepted")
	}
}

func TestUnlockKeychain(t *testing.T) {
	cases := []struct {
		name string
		pw   string
		r    *testutil.FakeRunner
		ok   bool
	}{
		{"plain", "s3cret pass\n", &testutil.FakeRunner{}, true},
		{"double quote", `bad"quote`, &testutil.FakeRunner{}, false},
		{"backslash", `bad\slash`, &testutil.FakeRunner{}, false},
		{"inner newline", "a\nb", &testutil.FakeRunner{}, false},
		{"empty", "\n", &testutil.FakeRunner{}, false},
		{"still locked", "pw", &testutil.FakeRunner{Fail: map[string]string{"show-keychain-info": "locked"}}, false},
		{"security fails", "pw", &testutil.FakeRunner{Fail: map[string]string{"security -i": "x"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pw := filepath.Join(t.TempDir(), "pw")
			os.WriteFile(pw, []byte(c.pw), 0o600)
			err := UnlockKeychain(context.Background(), c.r, "/k.keychain-db", pw)
			if (err == nil) != c.ok {
				t.Fatalf("err = %v", err)
			}
			for _, call := range c.r.Calls {
				if strings.Contains(strings.Join(call.Args, " "), "s3cret") || strings.Contains(strings.Join(call.Args, " "), "pw") {
					t.Fatal("password in argv")
				}
			}
			if c.ok && (!strings.Contains(string(c.r.Calls[0].Stdin), `-p "s3cret pass"`) || !c.r.Calls[0].Secret) {
				t.Fatalf("stdin: %q", c.r.Calls[0].Stdin)
			}
		})
	}
	if err := UnlockKeychain(context.Background(), &testutil.FakeRunner{}, "/k", "/missing/file"); err == nil {
		t.Fatal("missing file accepted")
	}
}
