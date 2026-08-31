// Package pinnedfs provides directory-handle-backed filesystem operations for
// Connector state and configuration transactions.
package pinnedfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const maxEdgeOpenAttempts = 16

// ErrUnsupported reports that the current platform cannot prove the required
// no-follow, ownership, link-count, and directory-fsync contracts.
var ErrUnsupported = errors.New("pinned filesystem transactions are unsupported on this platform")

// ErrNamespaceNotOwned reports a root-owned, non-writable namespace that is
// safe to read through a separately pinned snapshot but cannot host this
// process's transaction lock.
var ErrNamespaceNotOwned = errors.New("pinned transaction namespace is not owned by the effective user")

var syncPinnedParent = func(parent *os.Root, edgePath string) error {
	return syncPinnedDirectory(parent, edgePath)
}

var chmodPinnedChild = func(parent *os.Root, name string, mode os.FileMode) error {
	return parent.Chmod(name, mode)
}

var removePinnedChild = func(parent *os.Root, name string) error {
	return parent.Remove(name)
}

type pathEdge struct {
	parent    *os.Root
	name      string
	child     *os.Root
	childInfo os.FileInfo
	path      string
	created   bool
}

// Directory retains every directory handle from anchor to path. anchor is the
// filesystem root unless this process is confined below it -- see walk.
// Revalidating the complete edge chain detects final-directory and ancestor
// replacement before a caller mutates the retained namespace.
type Directory struct {
	path string
	// anchor records where the pinned chain begins. Used only for diagnostics
	// and tests; the field itself takes no part in revalidation.
	// After a confined recovery the chain covers anchor to path rather than /
	// to path: the components above the anchor were released with the failed
	// first walk and are not rechecked. That is sound, because the anchor
	// handle binds the subtree by inode, so a swap above it cannot redirect
	// any later operation. That argument covers operations after the open --
	// resolving the anchor path in the first place still traverses those
	// ancestors, and rests on the same confinement and ownership assumptions
	// as the band itself.
	anchor       string
	root         *os.Root
	roots        []*os.Root
	edges        []pathEdge
	exactMode    *os.FileMode
	requireOwner bool
	requireTrust bool
	allowSticky  bool
}

// Open pins an existing directory. Every path component must be a real
// directory; symlink components are rejected.
func Open(path string) (*Directory, error) {
	return walk(path, false, 0, nil, false, false, false)
}

// OpenTrusted pins an existing read-only namespace without creating or syncing
// path components. Every component must be owned by root or the effective user.
// Root-owned sticky shared ancestors may be traversed, but the final namespace
// itself must not be group/other writable.
func OpenTrusted(path string) (*Directory, error) {
	return walk(path, false, 0, nil, false, true, true)
}

// OpenPrivate pins an existing private directory without creating or syncing
// any path component. It is the read-only counterpart to EnsurePrivate.
func OpenPrivate(path string, mode os.FileMode) (*Directory, error) {
	if mode.Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private directory mode %04o grants group or other access", mode.Perm())
	}
	exact := mode.Perm()
	return walk(path, false, 0, &exact, true, true, true)
}

// Ensure creates missing path components one at a time and fsyncs each
// component's parent. Platform retry rules also fsync existing edges that may
// have survived an uncertain earlier fsync, so visibility is not mistaken for
// durability.
func Ensure(path string, mode os.FileMode) (*Directory, error) {
	return walk(path, true, mode.Perm(), nil, false, false, false)
}

// EnsurePrivate is Ensure with an exact owner-only final mode and owner check.
func EnsurePrivate(path string, mode os.FileMode) (*Directory, error) {
	if mode.Perm()&0o077 != 0 {
		return nil, fmt.Errorf("private directory mode %04o grants group or other access", mode.Perm())
	}
	exact := mode.Perm()
	return walk(path, true, exact, &exact, true, true, true)
}

// confinedAncestorError reports a path component this process is not permitted
// to open as a directory handle. It is distinct from an ordinary permission
// failure because it is recoverable: the namespace below it may still be
// reachable, in which case validation resumes there.
type confinedAncestorError struct {
	component string
	err       error
}

func (e *confinedAncestorError) Error() string { return e.err.Error() }
func (e *confinedAncestorError) Unwrap() error { return e.err }

// confinableError tags a wrapped component failure as recoverable when the
// underlying cause is a permission denial, which is how both an App Sandbox
// container boundary and a traverse-only (0111) ancestor present themselves.
//
// Recovery trusts the reachability topology, not the ancestor itself. A sandbox
// boundary is a confinement the kernel imposes; an arbitrary 0111 directory is
// not necessarily trustworthy and can be attacker-created. What makes the
// weaker case safe is that shallowestReachablePrefix refuses to resume below
// anything in the band that is not a real directory.
func confinableError(component string, wrapped, cause error) error {
	if !errors.Is(cause, fs.ErrPermission) {
		return wrapped
	}
	return &confinedAncestorError{component: component, err: wrapped}
}

func walk(path string, create bool, mode os.FileMode, exactMode *os.FileMode, requireOwner, requireTrust, allowSticky bool) (*Directory, error) {
	if err := requireSupportedPlatform(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("directory path is empty")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve directory path: %w", err)
	}
	abs = filepath.Clean(abs)
	if err := validateAbsoluteDirectoryPath(abs); err != nil {
		return nil, err
	}

	dir, err := walkFrom(directoryWalkAnchor(abs), abs, create, mode, exactMode, requireOwner, requireTrust, allowSticky)
	if err == nil {
		return dir, nil
	}

	// An ancestor this process cannot open cannot be validated -- and cannot be
	// attacked through either, because the same denial that hides it from this
	// walk is what confines the process to the namespace below it. macOS App
	// Sandbox is the case that matters: it resolves paths *through* ancestors it
	// refuses to open, so a walk that insists on a handle for every component
	// from / can never reach a sandboxed app's own container.
	//
	// Resume at the shallowest prefix that does open, so the largest reachable
	// part of the path is still validated edge by edge. This never weakens the
	// unconfined case: when the walk from / succeeds, it is used.
	var confined *confinedAncestorError
	if !supportsConfinedRecovery() || !errors.As(err, &confined) {
		return nil, err
	}
	// One fallback, not a loop: this recovers a single contiguous unreachable
	// band, which is the shape App Sandbox produces (denied ancestors, container
	// openable below them). A path that denies again *below* the anchor is not
	// re-anchored -- it fails closed rather than walking down re-anchoring at
	// each denial.
	anchor, ok := shallowestReachablePrefix(abs, confined.component, requireTrust, allowSticky)
	if !ok {
		return nil, err
	}
	return walkFrom(anchor, abs, create, mode, exactMode, requireOwner, requireTrust, allowSticky)
}

// validBandComponent applies the checks that survive without a pinned handle:
// a real, non-symlink directory, and for trusted callers the same ownership and
// writability rules the pinned walk enforces.
func validBandComponent(path string, requireTrust, allowSticky bool) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if err := validatePathComponent(path, info); err != nil {
		return false
	}
	if requireTrust {
		if err := validateTrustedDirectory(info, path, allowSticky); err != nil {
			return false
		}
	}
	return true
}

// shallowestReachablePrefix returns the shortest prefix of abs below denied
// that this process can open, so validation resumes as high as possible.
//
// Components in the band between denied and the returned anchor can never be
// pinned -- being unable to open them is what put us here -- so they are
// checked by absolute path instead. That is weaker than the pinned walk: it
// proves what the band looks like now, not that it cannot change afterwards.
// It exists to close one specific hole. os.OpenRoot resolves whatever path it
// is handed, so without this a symlink planted in the band would be traversed
// silently, which is the opposite of how a symlink is treated everywhere else
// here. Anything unreadable or not a real directory fails closed.
//
// Trusted callers additionally get the ownership and writability rules applied
// to the band. A component can be both unopenable and group/other-writable at
// once -- mode 0333 is traversable, not readable, and writable by anyone -- so
// without this an attacker-writable directory could sit in the resolved path
// precisely because being unopenable kept it out of the pinned walk.
func shallowestReachablePrefix(abs, denied string, requireTrust, allowSticky bool) (string, bool) {
	rel := strings.TrimPrefix(abs, denied)
	rel = strings.TrimPrefix(rel, string(filepath.Separator))
	if rel == "" {
		return "", false
	}
	// Re-check the denied component itself. openPathEdge validates it before
	// trying to open it, but only on that branch -- the Lstat branch produces a
	// confinableError before any validation runs. Rather than let the safety of
	// the recovery depend on which of the two sites fired, check it here.
	if !validBandComponent(denied, requireTrust, allowSticky) {
		return "", false
	}

	current := denied
	for _, name := range strings.Split(rel, string(filepath.Separator)) {
		current = filepath.Join(current, name)
		if !validBandComponent(current, requireTrust, allowSticky) {
			return "", false
		}
		root, err := os.OpenRoot(current)
		if err != nil {
			// Only a permission denial means "still inside the band", the same
			// rule confinableError uses. Anything else is a real failure on a
			// component Lstat just said is a directory, so stop rather than
			// descend past it.
			if errors.Is(err, fs.ErrPermission) {
				continue
			}
			return "", false
		}
		_ = root.Close()
		return current, true
	}
	return "", false
}

func walkFrom(anchor, abs string, create bool, mode os.FileMode, exactMode *os.FileMode, requireOwner, requireTrust, allowSticky bool) (_ *Directory, retErr error) {
	anchorRoot, err := os.OpenRoot(anchor)
	if err != nil {
		return nil, fmt.Errorf("open pinned walk anchor %s: %w", anchor, err)
	}
	dir := &Directory{
		path:         abs,
		anchor:       anchor,
		root:         anchorRoot,
		roots:        []*os.Root{anchorRoot},
		exactMode:    exactMode,
		requireOwner: requireOwner,
		requireTrust: requireTrust,
		allowSticky:  allowSticky,
	}
	defer func() {
		if retErr != nil {
			_ = dir.Close()
		}
	}()
	if requireTrust {
		anchorInfo, statErr := anchorRoot.Stat(".")
		if statErr != nil {
			return nil, fmt.Errorf("stat pinned walk anchor %s: %w", anchor, statErr)
		}
		if err := validateTrustedDirectoryRoot(anchorRoot, anchorInfo, anchor, allowSticky); err != nil {
			return nil, err
		}
	}

	relative := strings.TrimPrefix(abs, anchor)
	relative = strings.TrimPrefix(relative, string(filepath.Separator))
	if relative == "" {
		if err := dir.validateFinalAttributes(); err != nil {
			return nil, err
		}
		return dir, nil
	}

	currentPath := anchor
	for _, name := range strings.Split(relative, string(filepath.Separator)) {
		nextPath := filepath.Join(currentPath, name)
		edge, err := openPathEdge(dir.root, name, nextPath, create, mode)
		if err != nil {
			return nil, err
		}
		dir.edges = append(dir.edges, edge)
		dir.roots = append(dir.roots, edge.child)
		dir.root = edge.child

		if err := dir.validateEdges(); err != nil {
			return nil, err
		}
		if requireTrust {
			if err := validateTrustedDirectoryRoot(edge.child, edge.childInfo, edge.path, allowSticky); err != nil {
				return nil, err
			}
		}
		shouldSync := edge.created
		if create && !shouldSync {
			shouldSync, err = shouldRetryDirectoryEdgeSync(edge.child, edge.path)
			if err != nil {
				return nil, err
			}
		}
		if create && shouldSync {
			// Unix retries every existing edge. Windows retries only edges with
			// the protected ACL installed by createPinnedDirectory, so ordinary
			// volume and profile ancestors never need write access.
			if err := syncPinnedParent(edge.parent, edge.path); err != nil {
				return nil, fmt.Errorf("sync parent for directory edge %s: %w", edge.path, err)
			}
			if err := dir.validateEdges(); err != nil {
				return nil, err
			}
		}
		currentPath = nextPath
	}

	if err := dir.validateFinalAttributes(); err != nil {
		return nil, err
	}
	return dir, nil
}

func openPathEdge(parent *os.Root, name, path string, create bool, mode os.FileMode) (pathEdge, error) {
	for range maxEdgeOpenAttempts {
		created := false
		before, err := parent.Lstat(name)
		if errors.Is(err, os.ErrNotExist) && create {
			if err := createPinnedDirectory(parent, name, path, mode.Perm()); err != nil {
				if errors.Is(err, os.ErrExist) {
					continue
				}
				return pathEdge{}, fmt.Errorf("create directory component %s: %w", path, err)
			}
			created = true
			before, err = parent.Lstat(name)
		}
		if err != nil {
			return pathEdge{}, confinableError(path, fmt.Errorf("inspect directory component %s: %w", path, err), err)
		}
		if err := validatePathComponent(path, before); err != nil {
			return pathEdge{}, err
		}

		child, err := parent.OpenRoot(name)
		if err != nil {
			return pathEdge{}, confinableError(path, fmt.Errorf("open directory component %s: %w", path, err), err)
		}
		opened, err := child.Stat(".")
		if err != nil {
			_ = child.Close()
			return pathEdge{}, fmt.Errorf("stat opened directory component %s: %w", path, err)
		}
		after, err := parent.Lstat(name)
		if err != nil {
			_ = child.Close()
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return pathEdge{}, fmt.Errorf("recheck directory component %s: %w", path, err)
		}
		if err := validatePathComponent(path, after); err != nil {
			_ = child.Close()
			return pathEdge{}, err
		}
		if !os.SameFile(before, opened) || !os.SameFile(opened, after) {
			_ = child.Close()
			continue
		}
		return pathEdge{parent: parent, name: name, child: child, childInfo: opened, path: path, created: created}, nil
	}
	return pathEdge{}, fmt.Errorf("directory component %s changed during %d open attempts", path, maxEdgeOpenAttempts)
}

func wrapDirectoryCleanupError(path, operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s for directory component %s: %w", operation, path, err)
}

func validatePathComponent(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("directory component %s must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("path component %s is not a directory", path)
	}
	return nil
}

func (d *Directory) validateEdges() error {
	if d == nil || d.root == nil {
		return errors.New("pinned directory is closed")
	}
	for _, edge := range d.edges {
		opened, err := edge.child.Stat(".")
		if err != nil {
			return fmt.Errorf("stat pinned directory component %s: %w", edge.path, err)
		}
		entry, err := edge.parent.Lstat(edge.name)
		if err != nil {
			return fmt.Errorf("recheck directory component %s: %w", edge.path, err)
		}
		if err := validatePathComponent(edge.path, entry); err != nil {
			return err
		}
		if !os.SameFile(edge.childInfo, opened) || !os.SameFile(opened, entry) {
			return fmt.Errorf("directory component %s was replaced while pinned", edge.path)
		}
		if d.requireTrust {
			if err := validateTrustedDirectoryRoot(edge.child, opened, edge.path, d.allowSticky); err != nil {
				return err
			}
		}
	}
	return nil
}

func (d *Directory) validateFinalAttributes() error {
	if err := d.validateEdges(); err != nil {
		return err
	}
	info, err := d.root.Stat(".")
	if err != nil {
		return fmt.Errorf("stat pinned directory %s: %w", d.path, err)
	}
	return validateFinalDirectory(d.root, info, d.path, d.exactMode, d.requireOwner, d.requireTrust)
}

// ValidateCurrent revalidates every retained path edge and the final
// directory's required private attributes.
func (d *Directory) ValidateCurrent() error {
	return d.validateFinalAttributes()
}

// RequireOwnedNamespace rejects a foreign-owned or group/other-writable final
// directory before callers create a lock file inside it.
func (d *Directory) RequireOwnedNamespace() error {
	if err := d.ValidateCurrent(); err != nil {
		return err
	}
	info, err := d.root.Stat(".")
	if err != nil {
		return fmt.Errorf("stat transaction namespace %s: %w", d.path, err)
	}
	return validateOwnedDirectory(d.root, info, d.path)
}

// Path is the absolute public path pinned by this Directory.
func (d *Directory) Path() string {
	if d == nil {
		return ""
	}
	return d.path
}

// OpenFile opens name beneath the retained directory handle.
func (d *Directory) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	if err := d.ValidateCurrent(); err != nil {
		return nil, err
	}
	return openPinnedFile(d.root, name, flag, perm)
}

// Lstat reports on name without following its final symlink.
func (d *Directory) Lstat(name string) (os.FileInfo, error) {
	if err := d.ValidateCurrent(); err != nil {
		return nil, err
	}
	return d.root.Lstat(name)
}

// Readlink reads one link in the retained directory namespace. Callers that
// use the result for a security decision must bracket it with Lstat and
// ValidateCurrent checks because a link does not provide an open descriptor.
func (d *Directory) Readlink(name string) (string, error) {
	if err := d.ValidateCurrent(); err != nil {
		return "", err
	}
	return d.root.Readlink(name)
}

// ReadDirNames returns at most limit entry names from the retained directory.
// The extra read distinguishes an exact-size result from a namespace that
// exceeds the caller's bounded scan budget.
func (d *Directory) ReadDirNames(limit int) (names []string, retErr error) {
	if limit <= 0 {
		return nil, errors.New("directory entry limit must be positive")
	}
	if err := d.ValidateCurrent(); err != nil {
		return nil, err
	}
	dir, err := d.root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("open pinned directory for enumeration: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, dir.Close()) }()
	entries, err := dir.ReadDir(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("enumerate pinned directory: %w", err)
	}
	if len(entries) > limit {
		return nil, fmt.Errorf("pinned directory contains more than %d entries", limit)
	}
	names = make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	if err := d.ValidateCurrent(); err != nil {
		return nil, err
	}
	return names, nil
}

// Rename atomically renames oldName to newName inside the pinned directory.
func (d *Directory) Rename(oldName, newName string) error {
	if err := d.ValidateCurrent(); err != nil {
		return err
	}
	return d.root.Rename(oldName, newName)
}

// Remove removes name inside the pinned directory.
func (d *Directory) Remove(name string) error {
	if err := d.ValidateCurrent(); err != nil {
		return err
	}
	return d.root.Remove(name)
}

// Sync makes namespace mutations in the pinned directory durable.
func (d *Directory) Sync() error {
	if err := d.ValidateCurrent(); err != nil {
		return err
	}
	return syncPinnedDirectory(d.root, d.path)
}

// Close releases every retained directory handle.
func (d *Directory) Close() error {
	if d == nil || d.root == nil {
		return nil
	}
	var closeErr error
	for i := len(d.roots) - 1; i >= 0; i-- {
		closeErr = errors.Join(closeErr, d.roots[i].Close())
	}
	d.root = nil
	d.roots = nil
	d.edges = nil
	return closeErr
}

// IsNotExist reports whether err means an entry is absent.
func IsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
