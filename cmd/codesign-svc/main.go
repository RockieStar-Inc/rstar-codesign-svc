// Command codesign-svc is a self-hosted HTTP service for Developer ID code
// signing and notarization of macOS apps.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/clients"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/audit"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/auth"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/jobs"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/runner"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/server"
)

const usage = `usage:
  codesign-svc [-config path]                      run the service
  codesign-svc keys create -config path -name N -profiles p1,p2 [-expires 90d]
  codesign-svc keys list   -config path
  codesign-svc keys revoke -config path <id>
`

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keys" {
		if err := keysCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	fs := flag.NewFlagSet("codesign-svc", flag.ExitOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	cfgPath := fs.String("config", "config.yaml", "config file")
	fs.Parse(os.Args[1:])
	if err := serve(*cfgPath); err != nil {
		log.Fatal(err)
	}
}

func serve(cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}
	if err := cfg.CheckFiles(); err != nil {
		return err
	}
	al, err := audit.Open(cfg.AuditLog)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer al.Close()
	m, err := jobs.New(cfg, runner.Exec{}, al)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	m.Start(ctx)

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(cfg, auth.NewVerifier(cfg, nil), m, clients.SignScript).Handler(),
		ReadHeaderTimeout: 30 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Printf("codesign-svc listening on %s", cfg.Listen)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func keysCmd(args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	sub := args[0]
	fs := flag.NewFlagSet("keys "+sub, flag.ContinueOnError)
	cfgPath := fs.String("config", "config.yaml", "config file")
	name := fs.String("name", "", "key name (create)")
	profiles := fs.String("profiles", "", "comma-separated profile names (create)")
	expires := fs.String("expires", "90d", "lifetime such as 90d or 720h; 0 means never (create)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.AccessKeys.File == "" {
		return errors.New("access_keys.file is not set in the config")
	}
	if !cfg.AccessKeys.Enabled {
		fmt.Fprintln(os.Stderr, "note: access_keys.enabled is false; the service will not accept keys")
	}
	store := auth.NewKeyStore(cfg.AccessKeys.File)

	switch sub {
	case "create":
		if *name == "" || *profiles == "" {
			return errors.New("create needs -name and -profiles")
		}
		var profs []string
		for _, p := range strings.Split(*profiles, ",") {
			p = strings.TrimSpace(p)
			if _, ok := cfg.Profile(p); !ok {
				return fmt.Errorf("unknown profile %q", p)
			}
			profs = append(profs, p)
		}
		ttl, err := parseLifetime(*expires)
		if err != nil {
			return err
		}
		k, secret, err := store.Create(*name, profs, ttl)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "created key %s (%s). It is shown once; store it as a CI secret.\n", k.ID, k.Name)
		fmt.Println(secret)
	case "list":
		keys, err := store.List()
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tNAME\tPROFILES\tCREATED\tEXPIRES\tREVOKED")
		for _, k := range keys {
			exp := "never"
			if !k.Expires.IsZero() {
				exp = k.Expires.Format(time.RFC3339)
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%v\n", k.ID, k.Name, strings.Join(k.Profiles, ","), k.Created.Format(time.RFC3339), exp, k.Revoked)
		}
		return tw.Flush()
	case "revoke":
		if fs.NArg() != 1 {
			return errors.New("revoke needs one key id")
		}
		if err := store.Revoke(fs.Arg(0)); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "revoked", fs.Arg(0))
	default:
		return errors.New(usage)
	}
	return nil
}

func parseLifetime(s string) (time.Duration, error) {
	if s == "0" || s == "" {
		return 0, nil
	}
	if d, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(d)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("bad lifetime %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
