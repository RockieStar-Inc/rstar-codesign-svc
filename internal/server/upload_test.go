package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type uploadInfo struct {
	UploadID    string `json:"upload_id"`
	UploadToken string `json:"upload_token"`
	PartSize    int64  `json:"part_size"`
	Parts       int64  `json:"parts"`
}

func shaHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func (e *env) do(t *testing.T, method, path, token string, body []byte, length int64) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		r = bytes.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, r)
	if length != -2 {
		req.ContentLength = length
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func (e *env) startUpload(t *testing.T, token, profile string, size int64, sum string) (int, uploadInfo) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"profile": profile, "size": size, "sha256": sum})
	code, b := e.do(t, "POST", "/v1/uploads", token, body, int64(len(body)))
	var info uploadInfo
	json.Unmarshal(b, &info)
	return code, info
}

func (e *env) putPart(t *testing.T, info uploadInfo, n int, data []byte) int {
	t.Helper()
	code, _ := e.do(t, "PUT", fmt.Sprintf("/v1/uploads/%s/parts/%d", info.UploadID, n), info.UploadToken, data, int64(len(data)))
	return code
}

func (e *env) complete(t *testing.T, info uploadInfo) (int, map[string]string) {
	t.Helper()
	code, b := e.do(t, "POST", "/v1/uploads/"+info.UploadID+"/complete", info.UploadToken, nil, 0)
	out := map[string]string{}
	json.Unmarshal(b, &out)
	return code, out
}

func split(data []byte, size int64) [][]byte {
	var parts [][]byte
	for off := int64(0); off < int64(len(data)); off += size {
		parts = append(parts, data[off:min(off+size, int64(len(data)))])
	}
	return parts
}

func TestChunkedUploadEndToEnd(t *testing.T) {
	e := newEnv(t, 5, true)
	zip := appZip(t, "com.example.app")
	code, info := e.startUpload(t, "t1", "release", int64(len(zip)), shaHex(zip))
	if code != http.StatusCreated || info.PartSize != 4096 || info.Parts != int64(len(split(zip, 4096))) || info.Parts < 2 {
		t.Fatalf("start: %d %+v", code, info)
	}
	if e.m.Reserved() <= 0 {
		t.Fatal("no reservation while uploading")
	}
	for n, p := range split(zip, info.PartSize) {
		if c := e.putPart(t, info, n, p); c != http.StatusNoContent {
			t.Fatalf("part %d: %d", n, c)
		}
	}
	code, out := e.complete(t, info)
	if code != http.StatusAccepted || out["id"] == "" || out["job_token"] == "" {
		t.Fatalf("complete: %d %v", code, out)
	}
	if s := e.wait(t, out["id"], out["job_token"]); s.Status != "done" {
		t.Fatalf("job: %s", s.Error)
	}
	// The upload token is dead now.
	if c := e.putPart(t, info, 0, split(zip, info.PartSize)[0]); c != http.StatusNotFound {
		t.Fatalf("part after complete: %d", c)
	}
	if c, _ := e.complete(t, info); c != http.StatusNotFound {
		t.Fatalf("second complete: %d", c)
	}
}

func TestStartUploadValidation(t *testing.T) {
	zip := appZip(t, "com.example.app")
	sum := shaHex(zip)
	cases := []struct {
		name  string
		token string
		body  string
		want  int
	}{
		{"no token", "", fmt.Sprintf(`{"profile":"release","size":10,"sha256":"%s"}`, sum), 401},
		{"ref not allowed", "dev-branch", fmt.Sprintf(`{"profile":"release","size":10,"sha256":"%s"}`, sum), 403},
		{"pull_request_target", "prt", fmt.Sprintf(`{"profile":"release","size":10,"sha256":"%s"}`, sum), 403},
		{"unknown profile", "t1", fmt.Sprintf(`{"profile":"debug","size":10,"sha256":"%s"}`, sum), 403},
		{"key without the profile", "key-other", fmt.Sprintf(`{"profile":"release","size":10,"sha256":"%s"}`, sum), 403},
		{"bad sha", "t2", `{"profile":"release","size":10,"sha256":"abc"}`, 400},
		{"zero size", "t3", fmt.Sprintf(`{"profile":"release","size":0,"sha256":"%s"}`, sum), 400},
		{"negative size", "t3", fmt.Sprintf(`{"profile":"release","size":-5,"sha256":"%s"}`, sum), 400},
		{"too large", "t4", fmt.Sprintf(`{"profile":"release","size":%d,"sha256":"%s"}`, 1<<21, sum), 413},
		{"unknown field", "t5", fmt.Sprintf(`{"profile":"release","size":10,"sha256":"%s","entitlements":"x"}`, sum), 400},
		{"not JSON", "t6", `nope`, 400},
	}
	e := newEnv(t, 5, false)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, b := e.do(t, "POST", "/v1/uploads", c.token, []byte(c.body), int64(len(c.body)))
			if code != c.want {
				t.Fatalf("%d %s, want %d", code, b, c.want)
			}
			// A refused request reserves nothing.
			if e.m.Reserved() != 0 {
				t.Fatalf("reserved %d after a refused request", e.m.Reserved())
			}
		})
	}
	// The refused tokens were not burned (except where admission ran).
	if code, _ := e.startUpload(t, "t2", "release", int64(len(zip)), sum); code != http.StatusCreated {
		t.Fatalf("token after a 400: %d", code)
	}
	if code, _ := e.startUpload(t, "t2", "release", int64(len(zip)), sum); code != http.StatusUnauthorized {
		t.Fatalf("token reuse: %d", code)
	}
}

func TestStartUploadQueueFullKeepsToken(t *testing.T) {
	e := newEnv(t, 1, false)
	zip := appZip(t, "com.example.app")
	code, info := e.startUpload(t, "t1", "release", int64(len(zip)), shaHex(zip))
	if code != http.StatusCreated {
		t.Fatal(code)
	}
	if code, _ := e.startUpload(t, "t2", "release", int64(len(zip)), shaHex(zip)); code != http.StatusTooManyRequests {
		t.Fatalf("queue full: %d", code)
	}
	// Expire the first upload; the slot frees and t2 still works.
	e.srvNow(t, time.Now().Add(2*e.cfg.UploadTimeout))
	if code, _ := e.startUpload(t, "t2", "release", int64(len(zip)), shaHex(zip)); code != http.StatusCreated {
		t.Fatalf("retry: %d", code)
	}
	if c := e.putPart(t, info, 0, zip[:4096]); c != http.StatusNotFound {
		t.Fatalf("part on expired upload: %d", c)
	}
}

// srvNow moves the server clock and sweeps.
func (e *env) srvNow(t *testing.T, now time.Time) {
	t.Helper()
	e.api.now = func() time.Time { return now }
	e.api.SweepUploads()
}

func TestPartBounds(t *testing.T) {
	e := newEnv(t, 5, false)
	zip := appZip(t, "com.example.app")
	_, info := e.startUpload(t, "t1", "release", int64(len(zip)), shaHex(zip))
	parts := split(zip, info.PartSize)
	last := len(parts) - 1
	path := func(n string) string { return "/v1/uploads/" + info.UploadID + "/parts/" + n }
	cases := []struct {
		name   string
		path   string
		token  string
		body   []byte
		length int64
		want   int
	}{
		{"first part", path("0"), info.UploadToken, parts[0], int64(len(parts[0])), 204},
		{"same part again", path("0"), info.UploadToken, parts[0], int64(len(parts[0])), 204},
		{"last part, short", path(fmt.Sprint(last)), info.UploadToken, parts[last], int64(len(parts[last])), 204},
		{"negative", path("-1"), info.UploadToken, parts[0], int64(len(parts[0])), 400},
		{"past the end", path(fmt.Sprint(last + 1)), info.UploadToken, parts[0], int64(len(parts[0])), 400},
		{"not a number", path("x"), info.UploadToken, parts[0], int64(len(parts[0])), 400},
		{"short middle part", path("0"), info.UploadToken, parts[0][:100], 100, 400},
		{"last part with full size", path(fmt.Sprint(last)), info.UploadToken, parts[0], int64(len(parts[0])), 400},
		{"over part size", path("0"), info.UploadToken, make([]byte, info.PartSize+1), info.PartSize + 1, 413},
		{"no content length", path("0"), info.UploadToken, nil, -1, 411},
		{"wrong upload token", path("0"), "nope", parts[0], int64(len(parts[0])), 404},
		{"OIDC token is not an upload token", path("0"), "t1", parts[0], int64(len(parts[0])), 404},
		{"unknown upload", "/v1/uploads/" + strings.Repeat("0", 32) + "/parts/0", info.UploadToken, parts[0], int64(len(parts[0])), 404},
		{"bad upload id", "/v1/uploads/..%2f/parts/0", info.UploadToken, parts[0], int64(len(parts[0])), 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var body []byte = c.body
			if c.length == -1 {
				// Unknown length: send through a reader so the client uses chunked encoding.
				req, _ := http.NewRequest("PUT", e.srv.URL+c.path, io.MultiReader(bytes.NewReader(parts[0])))
				req.Header.Set("Authorization", "Bearer "+c.token)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				if resp.StatusCode != c.want {
					t.Fatalf("%d, want %d", resp.StatusCode, c.want)
				}
				return
			}
			if code, b := e.do(t, "PUT", c.path, c.token, body, c.length); code != c.want {
				t.Fatalf("%d %s, want %d", code, b, c.want)
			}
		})
	}
}

func TestCompleteChecks(t *testing.T) {
	zip := appZip(t, "com.example.app")
	cases := []struct {
		name     string
		size     int64
		sum      string
		skip     int // part not sent, or -1
		mutate   bool
		want     int
		thenOK   bool // send the missing part and complete again
		reserved bool // reservation still held after the failed complete
	}{
		{"missing part, then sent", int64(len(zip)), shaHex(zip), 1, false, 409, true, true},
		{"wrong sha", int64(len(zip)), strings.Repeat("a", 64), -1, false, 422, false, false},
		{"data changed in transit", int64(len(zip)), shaHex(zip), -1, true, 422, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, 5, false)
			code, info := e.startUpload(t, "t1", "release", c.size, c.sum)
			if code != http.StatusCreated {
				t.Fatal(code)
			}
			parts := split(zip, info.PartSize)
			for n, p := range parts {
				if n == c.skip {
					continue
				}
				if c.mutate && n == 0 {
					p = append([]byte{p[0] ^ 0xff}, p[1:]...)
				}
				if code := e.putPart(t, info, n, p); code != 204 {
					t.Fatalf("part %d: %d", n, code)
				}
			}
			code, out := e.complete(t, info)
			if code != c.want {
				t.Fatalf("complete: %d %v, want %d", code, out, c.want)
			}
			if (e.m.Reserved() > 0) != c.reserved {
				t.Fatalf("reserved = %d", e.m.Reserved())
			}
			if c.thenOK {
				if code := e.putPart(t, info, c.skip, parts[c.skip]); code != 204 {
					t.Fatal(code)
				}
				if code, out := e.complete(t, info); code != http.StatusAccepted {
					t.Fatalf("complete after resend: %d %v", code, out)
				}
				return
			}
			// After a failed check the upload is gone and its file deleted.
			if code := e.putPart(t, info, 0, parts[0]); code != http.StatusNotFound {
				t.Fatalf("part after abort: %d", code)
			}
			if ents, _ := os.ReadDir(e.m.UploadDir()); len(ents) != 0 {
				t.Fatalf("upload files left: %d", len(ents))
			}
		})
	}
}

func TestExpiredUploadReleases(t *testing.T) {
	e := newEnv(t, 1, false)
	zip := appZip(t, "com.example.app")
	_, info := e.startUpload(t, "t1", "release", int64(len(zip)), shaHex(zip))
	if c := e.putPart(t, info, 0, split(zip, info.PartSize)[0]); c != 204 {
		t.Fatal(c)
	}
	cases := []struct {
		name    string
		after   time.Duration
		expired bool
	}{
		{"still active", e.cfg.UploadTimeout / 2, false},
		{"idle past upload_timeout", 2 * e.cfg.UploadTimeout, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e.srvNow(t, time.Now().Add(c.after))
			if got := e.m.Reserved() == 0; got != c.expired {
				t.Fatalf("reserved = %d", e.m.Reserved())
			}
			_, err := os.Stat(filepath.Join(e.m.UploadDir(), "chunked-"+info.UploadID+".zip"))
			if os.IsNotExist(err) != c.expired {
				t.Fatalf("file exists = %v", err == nil)
			}
		})
	}
	if c, _ := e.complete(t, info); c != http.StatusNotFound {
		t.Fatalf("complete after expiry: %d", c)
	}
}

func TestConcurrentParts(t *testing.T) {
	e := newEnv(t, 5, true)
	zip := appZip(t, "com.example.app")
	_, info := e.startUpload(t, "t1", "release", int64(len(zip)), shaHex(zip))
	parts := split(zip, info.PartSize)
	var wg sync.WaitGroup
	errs := make(chan string, 3*len(parts))
	for round := 0; round < 3; round++ { // every part three times, all at once
		for n, p := range parts {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/v1/uploads/%s/parts/%d", e.srv.URL, info.UploadID, n), bytes.NewReader(p))
				req.Header.Set("Authorization", "Bearer "+info.UploadToken)
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					errs <- err.Error()
					return
				}
				resp.Body.Close()
				if resp.StatusCode != 204 {
					errs <- fmt.Sprintf("part %d: %d", n, resp.StatusCode)
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	code, out := e.complete(t, info)
	if code != http.StatusAccepted {
		t.Fatalf("complete: %d %v", code, out)
	}
	if s := e.wait(t, out["id"], out["job_token"]); s.Status != "done" {
		t.Fatal(s.Error)
	}
}

// TestUploadEdgeCases covers failures around the upload file and admission.
func TestUploadEdgeCases(t *testing.T) {
	zip := appZip(t, "com.example.app")
	sendAll := func(t *testing.T, e *env, info uploadInfo) {
		for n, p := range split(zip, info.PartSize) {
			if c := e.putPart(t, info, n, p); c != 204 {
				t.Fatalf("part %d: %d", n, c)
			}
		}
	}
	file := func(e *env, info uploadInfo) string {
		return filepath.Join(e.m.UploadDir(), "chunked-"+info.UploadID+".zip")
	}
	cases := []struct {
		name string
		run  func(t *testing.T, e *env, info uploadInfo) (int, []byte)
		want int
	}{
		{"complete while a part is in flight", func(t *testing.T, e *env, info uploadInfo) (int, []byte) {
			sendAll(t, e, info)
			u := e.api.uploads.m[info.UploadID]
			u.mu.Lock()
			u.inflight++
			u.mu.Unlock()
			defer func() { u.mu.Lock(); u.inflight--; u.mu.Unlock() }()
			return e.do(t, "POST", "/v1/uploads/"+info.UploadID+"/complete", info.UploadToken, nil, 0)
		}, 409},
		{"file shrank on disk", func(t *testing.T, e *env, info uploadInfo) (int, []byte) {
			sendAll(t, e, info)
			os.Truncate(file(e, info), 10)
			return e.do(t, "POST", "/v1/uploads/"+info.UploadID+"/complete", info.UploadToken, nil, 0)
		}, 422},
		{"file gone at complete", func(t *testing.T, e *env, info uploadInfo) (int, []byte) {
			sendAll(t, e, info)
			os.Remove(file(e, info))
			return e.do(t, "POST", "/v1/uploads/"+info.UploadID+"/complete", info.UploadToken, nil, 0)
		}, 500},
		{"file gone at part", func(t *testing.T, e *env, info uploadInfo) (int, []byte) {
			os.Remove(file(e, info))
			p := split(zip, info.PartSize)[0]
			return e.do(t, "PUT", "/v1/uploads/"+info.UploadID+"/parts/0", info.UploadToken, p, int64(len(p)))
		}, 400},
		{"complete after the upload was closed", func(t *testing.T, e *env, info uploadInfo) (int, []byte) {
			u := e.api.uploads.m[info.UploadID]
			u.mu.Lock()
			u.closed = true
			u.mu.Unlock()
			p := split(zip, info.PartSize)[0]
			if c, _ := e.do(t, "PUT", "/v1/uploads/"+info.UploadID+"/parts/0", info.UploadToken, p, int64(len(p))); c != 404 {
				t.Fatalf("part on closed upload: %d", c)
			}
			return e.do(t, "POST", "/v1/uploads/"+info.UploadID+"/complete", info.UploadToken, nil, 0)
		}, 404},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, 5, false)
			code, info := e.startUpload(t, "t1", "release", int64(len(zip)), shaHex(zip))
			if code != http.StatusCreated {
				t.Fatal(code)
			}
			if got, b := c.run(t, e, info); got != c.want {
				t.Fatalf("%d %s, want %d", got, b, c.want)
			}
		})
	}
}

func TestStartUploadAdmission(t *testing.T) {
	zip := appZip(t, "com.example.app")
	cases := []struct {
		name string
		free func(string) (uint64, error)
		want int
	}{
		{"low disk", func(string) (uint64, error) { return 0, nil }, 503},
		{"statfs error", func(string) (uint64, error) { return 0, os.ErrPermission }, 500},
		{"room", func(string) (uint64, error) { return 1 << 62, nil }, 201},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, 5, false)
			e.m.FreeBytes = c.free
			if code, _ := e.startUpload(t, "t1", "release", int64(len(zip)), shaHex(zip)); code != c.want {
				t.Fatalf("%d, want %d", code, c.want)
			}
			if c.want != 201 && e.m.Reserved() != 0 {
				t.Fatal("reservation kept")
			}
		})
	}
}

func TestRunStopsWithContext(t *testing.T) {
	e := newEnv(t, 1, false)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { e.api.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
}
