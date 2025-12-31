package main

import (
        "bufio"
        "crypto/sha256"
        "fmt"
        "io"
        "log"
        "os"
        "os/exec"
        "path/filepath"
        "strings"
        "sync"

        "github.com/fsnotify/fsnotify"
)

/*
AUTHORIZED USERS
Only root is allowed.
*/
var authorizedUIDs = map[uint32]bool{
        0: true, // root
}

// Paths to monitor
var watchList = []string{
        "/tmp/fim-test",
}

// watchedSet tracks directories already added
type watchedSet struct {
        mu sync.Mutex
        m  map[string]struct{}
}

func newWatchedSet() *watchedSet {
        return &watchedSet{m: make(map[string]struct{})}
}
func (ws *watchedSet) has(path string) bool {
        ws.mu.Lock()
        defer ws.mu.Unlock()
        _, ok := ws.m[path]
        return ok
}
func (ws *watchedSet) add(path string) {
        ws.mu.Lock()
        defer ws.mu.Unlock()
        ws.m[path] = struct{}{}
}

// Recursively add directories to watcher
func addAllDirs(w *fsnotify.Watcher, root string, watched *watchedSet) {
        filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
                if err != nil {
                        return nil
                }
                if d.IsDir() && !watched.has(path) {
                        if err := w.Add(path); err == nil {
                                watched.add(path)
                                log.Printf("watching: %s", path)
                        }
                }
                return nil
        })
}

// Hash file contents
func hashFile(path string) (string, error) {
        f, err := os.Open(path)
        if err != nil {
                return "", err
        }
        defer f.Close()

        h := sha256.New()
        if _, err := io.Copy(h, f); err != nil {
                return "", err
        }
        return fmt.Sprintf("%x", h.Sum(nil)), nil
}

// Baseline all existing files
func baselineAllFiles(root string) {
        filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
                if err != nil || d.IsDir() {
                        return nil
                }
                h, err := hashFile(path)
                if err == nil {
                        baseline[path] = h
                        log.Printf("[BASELINED] %s", path)
                }
                return nil
        })
}

// Audit event structure
type AuditEvent struct {
        Path string
        AUID uint32
        Exe  string
        Comm string
}

// Fetch latest audit event and correctly extract AUID
func findRecentAuditEvent(path string) (*AuditEvent, error) {
        cmd := exec.Command("ausearch", "-k", "fim_test", "-ts", "recent", "-i")
        out, err := cmd.Output()
        if err != nil {
                return nil, err
        }

        scanner := bufio.NewScanner(strings.NewReader(string(out)))
        var evt AuditEvent

        for scanner.Scan() {
                line := scanner.Text()

                if strings.Contains(line, "name="+path) || strings.Contains(line, "name="+filepath.Base(path)) {
                        evt.Path = path
                }

                if strings.Contains(line, " auid=") {
                        for _, field := range strings.Fields(line) {
                                if strings.HasPrefix(field, "auid=") {
                                        fmt.Sscanf(field, "auid=%d", &evt.AUID)
                                }
                                if strings.HasPrefix(field, "uid=") {
                                        fmt.Sscanf(field, "uid=%d", &evt.AUID)
                                }
                        }
                }

                if strings.Contains(line, "exe=") {
                        parts := strings.Split(line, "exe=")
                        if len(parts) > 1 {
                                evt.Exe = strings.Fields(parts[1])[0]
                        }
                }
        }

        if evt.Path == "" {
                return nil, fmt.Errorf("no matching audit event")
        }
        return &evt, nil
}

var baseline = make(map[string]string)

func main() {
        watcher, err := fsnotify.NewWatcher()
        if err != nil {
                log.Fatal(err)
        }
        defer watcher.Close()

        tracked := newWatchedSet()

        for _, root := range watchList {
                addAllDirs(watcher, root, tracked)
                baselineAllFiles(root)
        }

        go func() {
                for {
                        select {
                        case event := <-watcher.Events:
                                if event.Op&fsnotify.Write == fsnotify.Write {
                                        newHash, err := hashFile(event.Name)
                                        if err != nil {
                                                continue
                                        }

                                        oldHash := baseline[event.Name]
                                        if oldHash == "" {
                                                baseline[event.Name] = newHash
                                                log.Printf("[BASELINE CREATED] %s", event.Name)
                                                continue
                                        }

                                        if oldHash != newHash {
                                                auditEvt, err := findRecentAuditEvent(event.Name)
                                                if err != nil {
                                                        log.Printf("[AUDIT UNKNOWN] %s", event.Name)
                                                        continue
                                                }

                                                if authorizedUIDs[auditEvt.AUID] {
                                                        log.Printf("[AUTHORIZED CHANGE] %s by uid=%d exe=%s",
                                                                event.Name, auditEvt.AUID, auditEvt.Exe)
                                                        baseline[event.Name] = newHash
                                                } else {
                                                        log.Printf("[UNAUTHORIZED CHANGE 🚨] %s by uid=%d exe=%s",
                                                                event.Name, auditEvt.AUID, auditEvt.Exe)
                                                }
                                        }
                                }

                                if event.Op&fsnotify.Create == fsnotify.Create {
                                        info, _ := os.Stat(event.Name)
                                        if info != nil && info.IsDir() {
                                                addAllDirs(watcher, event.Name, tracked)
                                                baselineAllFiles(event.Name)
                                        }
                                        log.Printf("[CREATED] %s", event.Name)
                                }

                                if event.Op&fsnotify.Remove == fsnotify.Remove {
                                        delete(baseline, event.Name)
                                        log.Printf("[DELETED] %s", event.Name)
                                }

                        case err := <-watcher.Errors:
                                log.Printf("watcher error: %v", err)
                        }
                }
        }()

        log.Printf("Watching paths: %v", watchList)
        select {}
}
