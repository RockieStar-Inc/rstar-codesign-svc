package jobs

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/archive"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/config"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/notary"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/runner"
	"github.com/RockieStar-Inc/rstar-codesign-svc/internal/sign"
)

// Notarization stages, saved so a restart can resume polling.
const (
	stageApp = "app"
	stageDMG = "dmg"
)

func (m *Manager) process(ctx context.Context, id string) {
	m.mu.Lock()
	j, ok := m.jobs[id]
	m.mu.Unlock()
	if !ok {
		return
	}
	if j.StartedAt.IsZero() {
		m.update(j, func(j *Job) { j.StartedAt = m.now().UTC() })
	}
	ctx, cancel := context.WithDeadline(ctx, j.StartedAt.Add(m.cfg.JobTimeout))
	defer cancel()
	err := m.pipeline(ctx, j)
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		err = fmt.Errorf("job deadline of %s exceeded: %w", m.cfg.JobTimeout, err)
	}
	if err != nil && errors.Is(ctx.Err(), context.Canceled) {
		// Service is stopping. Leave the job as it is; New decides on restart.
		return
	}
	m.finish(j, err)
}

// pipeline runs the job. A job resumed after a restart has Status
// notarizing, a Stage and a NotarySubmission; it continues from there.
func (m *Manager) pipeline(ctx context.Context, j *Job) error {
	prof, ok := m.cfg.Profile(j.Profile)
	if !ok {
		return fmt.Errorf("profile %q no longer exists", j.Profile)
	}
	// Unlock first, so resumed jobs can sign the DMG too.
	if m.pwFile != "" {
		if err := sign.UnlockKeychain(ctx, m.run, prof.Keychain, m.pwFile); err != nil {
			return err
		}
	}
	resume := j.Status == Notarizing && j.NotarySubmission != ""
	var app string
	var err error
	if resume {
		if app, err = archive.FindApp(filepath.Join(m.workDir(j.ID), "src")); err != nil {
			return fmt.Errorf("resume: %w", err)
		}
	} else if app, err = m.signApp(ctx, j, prof); err != nil {
		return err
	}
	if !resume || j.Stage == stageApp {
		if err := m.notarizeApp(ctx, j, prof, app); err != nil {
			return err
		}
	}
	if prof.DMG {
		return m.makeDMG(ctx, j, prof, app)
	}
	return nil
}

func (m *Manager) signApp(ctx context.Context, j *Job, prof config.Profile) (string, error) {
	m.setStatus(j, Signing)
	work := m.workDir(j.ID)
	if err := os.MkdirAll(m.outDir(j.ID), 0o700); err != nil {
		return "", err
	}
	src := filepath.Join(work, "src")
	if err := os.Mkdir(src, 0o700); err != nil {
		return "", err
	}
	lim := archive.Limits{
		MaxExpandedBytes: m.cfg.MaxExpandedBytes, MaxFiles: m.cfg.MaxFiles,
		FreeBytes: m.FreeBytes, MinFreeBytes: m.cfg.MinFreeBytes,
	}
	if err := archive.Unzip(filepath.Join(work, "input.zip"), src, lim); err != nil {
		return "", fmt.Errorf("unzip: %w", err)
	}
	if err := os.Remove(filepath.Join(work, "input.zip")); err != nil {
		return "", err
	}
	app, err := archive.FindApp(src)
	if err != nil {
		return "", err
	}
	if err := archive.CheckFrameworks(app); err != nil {
		return "", err
	}
	bundleID, err := sign.BundleID(ctx, m.run, app)
	if err != nil {
		return "", err
	}
	m.update(j, func(j *Job) { j.BundleID, j.Name = bundleID, strings.TrimSuffix(filepath.Base(app), ".app") })
	if !sign.BundleIDAllowed(prof, bundleID) {
		return "", fmt.Errorf("bundle id %s is not allowed for profile %s", bundleID, prof.Name)
	}
	items, err := sign.Plan(ctx, m.run, app, prof)
	if err != nil {
		return "", err
	}
	if err := sign.CheckNestedIDs(ctx, m.run, items, bundleID); err != nil {
		return "", err
	}
	report := sign.Report(prof, items)
	for _, ri := range report {
		if ri.Warning != "" {
			log.Printf("job %s: WARNING %s: %s", j.ID, ri.Path, ri.Warning)
		}
	}
	m.update(j, func(j *Job) { j.SigningReport = report })
	if err := sign.Sign(ctx, m.run, prof, items); err != nil {
		return "", err
	}
	if err := sign.Verify(ctx, m.run, app, prof.TeamID); err != nil {
		return "", err
	}
	return app, nil
}

// submitOrResume returns the submission id for stage: the saved one when
// resuming, else a new one from submit, saved at once.
func (m *Manager) submitOrResume(ctx context.Context, j *Job, stage string, submit func() (string, error)) (string, error) {
	if j.Stage == stage && j.NotarySubmission != "" {
		return j.NotarySubmission, nil
	}
	id, err := submit()
	if err != nil {
		return "", err
	}
	m.update(j, func(j *Job) { j.Status, j.Stage, j.NotarySubmission = Notarizing, stage, id })
	return id, nil
}

func (m *Manager) notarizeApp(ctx context.Context, j *Job, prof config.Profile, app string) error {
	id, err := m.submitOrResume(ctx, j, stageApp, func() (string, error) {
		m.setStatus(j, Notarizing)
		z := filepath.Join(m.workDir(j.ID), "notarize.zip")
		if err := archive.Zip(ctx, m.run, app, z); err != nil {
			return "", err
		}
		return notary.Submit(ctx, m.run, prof.Notary, z)
	})
	if err != nil {
		return err
	}
	if err := notary.Wait(ctx, m.run, prof.Notary, id, m.PollInterval); err != nil {
		return err
	}
	if err := notary.Staple(ctx, m.run, app); err != nil {
		return err
	}
	if err := notary.AssessApp(ctx, m.run, app); err != nil {
		return err
	}
	zipPath := filepath.Join(m.outDir(j.ID), j.Name+".zip")
	os.Remove(zipPath)
	if err := archive.Zip(ctx, m.run, app, zipPath); err != nil {
		return err
	}
	sum, err := archive.SHA256File(zipPath)
	if err != nil {
		return err
	}
	m.update(j, func(j *Job) { j.Artifacts["zip"] = &Artifact{SHA256: sum, NotaryID: id} })
	return nil
}

func (m *Manager) makeDMG(ctx context.Context, j *Job, prof config.Profile, app string) error {
	dmgPath := filepath.Join(m.outDir(j.ID), j.Name+".dmg")
	id, err := m.submitOrResume(ctx, j, stageDMG, func() (string, error) {
		staging := filepath.Join(m.workDir(j.ID), "dmg")
		os.RemoveAll(staging)
		if err := m.buildDMG(ctx, prof.VolumeName, j.Name, app, staging, dmgPath); err != nil {
			return "", err
		}
		if err := sign.SignFile(ctx, m.run, prof, dmgPath); err != nil {
			return "", fmt.Errorf("sign dmg: %w", err)
		}
		if err := sign.CheckTeam(ctx, m.run, dmgPath, prof.TeamID); err != nil {
			return "", err
		}
		return notary.Submit(ctx, m.run, prof.Notary, dmgPath)
	})
	if err != nil {
		return err
	}
	if err := notary.Wait(ctx, m.run, prof.Notary, id, m.PollInterval); err != nil {
		return fmt.Errorf("dmg: %w", err)
	}
	if err := notary.Staple(ctx, m.run, dmgPath); err != nil {
		return err
	}
	if err := notary.AssessDMG(ctx, m.run, dmgPath); err != nil {
		return err
	}
	sum, err := archive.SHA256File(dmgPath)
	if err != nil {
		return err
	}
	m.update(j, func(j *Job) { j.Artifacts["dmg"] = &Artifact{SHA256: sum, NotaryID: id} })
	return nil
}

// buildDMG makes a compressed disk image with the app and an /Applications link.
func (m *Manager) buildDMG(ctx context.Context, volume, name, app, staging, dst string) error {
	if volume == "" {
		volume = name
	}
	if err := os.MkdirAll(staging, 0o700); err != nil {
		return err
	}
	if err := archive.Copy(ctx, m.run, app, filepath.Join(staging, filepath.Base(app))); err != nil {
		return err
	}
	if err := os.Symlink("/Applications", filepath.Join(staging, "Applications")); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(staging, ".metadata_never_index"), nil, 0o644); err != nil {
		return err
	}
	cmd := runner.Cmd{Name: "hdiutil", Args: []string{"create", "-volname", volume, "-srcfolder", staging, "-format", "UDZO", "-ov", dst}, Timeout: runner.HdiutilTimeout}
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(m.retryDelay):
			}
		}
		var res runner.Result
		res, err = m.run.Run(ctx, cmd)
		if err == nil {
			return nil
		}
		if !strings.Contains(string(res.Stderr)+err.Error(), "Resource busy") {
			break
		}
	}
	return fmt.Errorf("hdiutil create: %w", err)
}
