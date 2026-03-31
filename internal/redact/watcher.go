package redact

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchBlocklistDir watches a directory for changes to .yaml/.yml files and
// reloads the blocklist into the holder on each change. It also watches
// resolved symlink targets so that changes to linked files are detected.
//
// Returns a stop function that shuts down the watcher.
func WatchBlocklistDir(dir string, holder *BlocklistHolder) (func(), error) {
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve blocklist dir: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("create watcher: %w", err)
	}

	// Watch the directory itself.
	if err := watcher.Add(resolved); err != nil {
		_ = watcher.Close()
		return nil, fmt.Errorf("watch dir: %w", err)
	}

	// Also watch individual symlink targets so content changes are detected.
	watchSymlinkTargets(watcher, resolved)

	done := make(chan struct{})
	go func() {
		var debounce *time.Timer
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Only react to yaml file changes.
				ext := strings.ToLower(filepath.Ext(event.Name))
				if ext != ".yaml" && ext != ".yml" {
					continue
				}
				if debounce != nil {
					debounce.Stop()
				}
				debounce = time.AfterFunc(100*time.Millisecond, func() {
					bl, err := LoadBlocklistDir(dir)
					if err != nil {
						fmt.Fprintf(os.Stderr, "hushterm: blocklist reload: %v\n", err)
						return
					}
					holder.Store(bl)
					// Re-watch symlink targets in case new symlinks were added.
					watchSymlinkTargets(watcher, resolved)
				})
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Fprintf(os.Stderr, "hushterm: watcher error: %v\n", err)
			case <-done:
				return
			}
		}
	}()

	stop := func() {
		close(done)
		_ = watcher.Close()
	}
	return stop, nil
}

// watchSymlinkTargets resolves symlinks in the directory and watches their
// real paths so that changes to symlink targets fire events.
func watchSymlinkTargets(watcher *fsnotify.Watcher, dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, de := range entries {
		name := de.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		fullPath := filepath.Join(dir, name)
		realPath, err := filepath.EvalSymlinks(fullPath)
		if err != nil {
			continue
		}
		// If it's a symlink (resolved path differs), watch the target's directory.
		if realPath != fullPath {
			targetDir := filepath.Dir(realPath)
			// Ignore errors — may already be watched.
			_ = watcher.Add(targetDir)
		}
	}
}
