package agentstate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"

	qurl "github.com/layervai/qurl-go/qurl"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

const (
	// AgentStateFile is the SDK-owned plaintext credential envelope used by the
	// explicit file provider. The directory is selected explicitly or with
	// QURL_CONNECTOR_STATE_DIR.
	AgentStateFile = "agent_state.json"

	// SealedAgentStateFile is the SDK-owned full-state envelope used by every
	// KMS or attested provider. It contains the device API credential as well as
	// the native UDP identity and assignment; only its random 32-byte DEK crosses
	// the cloud-provider boundary.
	SealedAgentStateFile = "agent_state.sealed.json"

	wrappedAgentStateKeyVersion = 1
	wrappedKeyPurpose           = "qurl-go/agent-state-dek"
)

// prepareNativeStateDir establishes creation durability and returns the
// Connector-owned state namespace capability. SDKStore retains it alongside
// qurl-go's independently pinned local-store capability for their shared
// lifetime.
var prepareNativeStateDir = func(path string) (*pinnedfs.Directory, error) {
	return pinnedfs.EnsurePrivate(path, 0o700)
}

// SDKStore owns one explicit qurl-go local store and the Connector state
// namespace from which it was constructed. It deliberately does not implement
// qurl.AgentStateStore: handing a wrapper to qurl-go would hide the concrete
// store's package-private setup-lock capability. Call Handoff at each lifecycle
// boundary and retain this owner until every returned client and runtime binding
// has finished.
type SDKStore struct {
	mu         sync.RWMutex
	state      qurl.AgentStateStore
	continuity qurl.AgentStateContinuity
	namespace  *pinnedfs.Directory

	closeOnce sync.Once
	closeErr  error
}

// SDKStateReader owns the Connector state namespace and the SDK's narrow
// read-only state reader for their shared lifetime. Unlike SDKStore it exposes
// no Save, marker, setup-lock, or repair capability.
type SDKStateReader struct {
	mu        sync.RWMutex
	state     qurl.AgentStateReader
	namespace *pinnedfs.Directory

	closeOnce sync.Once
	closeErr  error
}

var _ qurl.AgentStateReader = (*SDKStateReader)(nil)

// Handoff validates both retained namespace capabilities before returning the
// original concrete qurl-go store. qurl-go must receive that exact dynamic
// value so its setup-lock and operation-lease contracts remain active.
func (s *SDKStore) Handoff() (qurl.AgentStateStore, error) {
	if s == nil {
		return nil, fmt.Errorf("%w: Connector SDK state store is not open", qurl.ErrAgentStateContinuity)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.validateContinuityLocked(); err != nil {
		return nil, err
	}
	return s.state, nil
}

// ValidateContinuity proves that both Connector and qurl-go still resolve the
// configured state path to their retained directory capabilities. The
// Connector check is repeated after the SDK check so a replacement during the
// handoff window fails closed.
func (s *SDKStore) ValidateContinuity() error {
	if s == nil {
		return fmt.Errorf("%w: Connector SDK state store is not open", qurl.ErrAgentStateContinuity)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.validateContinuityLocked()
}

// LoadRegistrationRefreshMarker reads the self-heal episode from the same
// retained state namespace that owns the qurl-go store.
func (s *SDKStore) LoadRegistrationRefreshMarker() (RefreshMarker, bool, error) {
	var marker RefreshMarker
	var present bool
	if err := s.withRefreshMarkerMutation(func(namespace *pinnedfs.Directory) error {
		var err error
		marker, present, err = loadRegistrationRefreshMarker(namespace)
		return err
	}); err != nil {
		return RefreshMarker{}, false, err
	}
	return marker, present, nil
}

// RequestRegistrationRefresh durably opens one automatic recovery episode in the
// retained state namespace.
func (s *SDKStore) RequestRegistrationRefresh(reason string) error {
	return s.withRefreshMarkerMutation(func(namespace *pinnedfs.Directory) error {
		return requestRegistrationRefresh(namespace, reason)
	})
}

// MarkRegistrationRefreshAttempted advances the persisted retry schedule
// before Hub I/O.
func (s *SDKStore) MarkRegistrationRefreshAttempted() error {
	return s.withRefreshMarkerMutation(markRegistrationRefreshAttempted)
}

// MarkRegistrationRefreshSucceeded records the authenticated assignment
// handoff while retaining the marker until the route serves.
func (s *SDKStore) MarkRegistrationRefreshSucceeded() error {
	return s.withRefreshMarkerMutation(markRegistrationRefreshSucceeded)
}

// ClearRegistrationRefreshMarker closes the episode only after a confirmed
// healthy Connector-server login.
func (s *SDKStore) ClearRegistrationRefreshMarker() error {
	return s.withRefreshMarkerMutation(clearRegistrationRefreshMarker)
}

func (s *SDKStore) withRefreshMarkerMutation(fn func(*pinnedfs.Directory) error) error {
	if s == nil {
		return fmt.Errorf("%w: Connector SDK state store is not open", qurl.ErrAgentStateContinuity)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if err := s.validateContinuityLocked(); err != nil {
		return err
	}
	if err := fn(s.namespace); err != nil {
		return err
	}
	return s.validateContinuityLocked()
}

func (s *SDKStore) validateContinuityLocked() error {
	if s == nil || s.namespace == nil || s.state == nil || s.continuity == nil {
		return fmt.Errorf("%w: Connector SDK state store is not open", qurl.ErrAgentStateContinuity)
	}
	if err := s.namespace.ValidateCurrent(); err != nil {
		return fmt.Errorf("%w: validate Connector state namespace: %w", qurl.ErrAgentStateContinuity, err)
	}
	if err := s.continuity.ValidateContinuity(); err != nil {
		return err
	}
	if err := s.namespace.ValidateCurrent(); err != nil {
		return fmt.Errorf("%w: revalidate Connector state namespace: %w", qurl.ErrAgentStateContinuity, err)
	}
	return nil
}

// Close releases qurl-go's local-store capability first, then the containing
// Connector namespace. It is idempotent and preserves every close/continuity
// error for the caller.
func (s *SDKStore) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		var namespaceContinuityBeforeCloseErr error
		if s.namespace != nil {
			namespaceContinuityBeforeCloseErr = s.namespace.ValidateCurrent()
			if namespaceContinuityBeforeCloseErr != nil {
				namespaceContinuityBeforeCloseErr = fmt.Errorf("%w: validate Connector state namespace before SDK close: %w", qurl.ErrAgentStateContinuity, namespaceContinuityBeforeCloseErr)
			}
		}
		var sdkCloseErr error
		if s.continuity != nil {
			sdkCloseErr = s.continuity.Close()
		}
		// qurl-go Close may block while an in-flight state operation drains. The
		// configured namespace can be replaced during that wait, so the
		// pre-close check alone cannot authorize teardown as continuous.
		var namespaceContinuityAfterCloseErr error
		if s.namespace != nil {
			namespaceContinuityAfterCloseErr = s.namespace.ValidateCurrent()
			if namespaceContinuityAfterCloseErr != nil {
				namespaceContinuityAfterCloseErr = fmt.Errorf("%w: validate Connector state namespace after SDK close: %w", qurl.ErrAgentStateContinuity, namespaceContinuityAfterCloseErr)
			}
		}
		var namespaceCloseErr error
		if s.namespace != nil {
			namespaceCloseErr = s.namespace.Close()
		}
		s.closeErr = errors.Join(
			sdkCloseErr,
			namespaceContinuityBeforeCloseErr,
			namespaceContinuityAfterCloseErr,
			namespaceCloseErr,
		)
		s.state = nil
		s.continuity = nil
		s.namespace = nil
	})
	return s.closeErr
}

// ValidateSDKStoreLayout performs the same provider/envelope conflict checks
// as NewSDKStore without constructing a provider or opening qurl-go state.
// Sibling continuity journals call it before their first durable write.
func ValidateSDKStoreLayout(dir string) (retErr error) {
	dir = ResolveDir(dir)
	namespace, err := prepareNativeStateDir(dir)
	if err != nil {
		return fmt.Errorf("prepare native agent state directory: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, namespace.Close())
	}()
	_, err = validateSDKStoreLayoutInNamespace(namespace)
	return err
}

// ValidateSDKStoreLayoutReadOnly performs the same provider/envelope conflict
// checks without creating or syncing the state namespace. It is used by
// display-only commands that must not repair missing durability artifacts.
func ValidateSDKStoreLayoutReadOnly(dir string) (retErr error) {
	dir = ResolveDir(dir)
	namespace, err := pinnedfs.OpenPrivate(dir, 0o700)
	if err != nil {
		return fmt.Errorf("open native agent state directory read-only: %w", err)
	}
	defer func() {
		retErr = errors.Join(retErr, namespace.Close())
	}()
	_, err = validateSDKStoreLayoutInNamespace(namespace)
	return err
}

// OpenSDKStateReader opens the configured plaintext or sealed SDK envelope
// without creating, chmodding, syncing, locking, repairing, or writing any
// filesystem object. The returned reader retains both qurl-go's pinned state
// directory and the Connector's containing namespace so a path replacement
// across either layer fails closed.
func OpenSDKStateReader(dir, configuredAgentID string) (_ qurl.AgentStateReader, retErr error) {
	dir = ResolveDir(dir)
	namespace, err := pinnedfs.OpenPrivate(dir, 0o700)
	if err != nil {
		return nil, fmt.Errorf("open native agent state directory read-only: %w", err)
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, namespace.Close())
		}
	}()

	providerName, err := validateSDKStoreLayoutInNamespace(namespace)
	if err != nil {
		return nil, err
	}

	var reader qurl.AgentStateReader
	if providerName == KeyProviderFile {
		reader, err = qurl.OpenFileAgentStateReadOnly(filepath.Join(dir, AgentStateFile))
		if err != nil {
			return nil, fmt.Errorf("open plaintext agent state read-only: %w", err)
		}
	} else {
		provider, providerErr := keyProviderForName(providerName)
		if providerErr != nil {
			return nil, fmt.Errorf("initialize %s state key unwrapper: %w", providerName, providerErr)
		}
		opts := sealedAgentIDOptions(configuredAgentID)
		reader, err = qurl.OpenSealedFileAgentStateReadOnly(
			filepath.Join(dir, SealedAgentStateFile),
			providerName,
			&sdkStateKeyWrapper{provider: provider},
			opts...,
		)
		if err != nil {
			return nil, fmt.Errorf("open sealed agent state read-only: %w", err)
		}
	}

	owner := &SDKStateReader{state: reader, namespace: namespace}
	if err := owner.validateContinuityLocked(); err != nil {
		return nil, errors.Join(err, reader.Close())
	}
	return owner, nil
}

// LoadAgentState reads through the SDK's retained read-only descriptor between
// checks of the containing Connector namespace. If continuity is lost after a
// successful decode, the owned state is cleared before the error is returned.
func (r *SDKStateReader) LoadAgentState(ctx context.Context) (*qurl.AgentState, error) {
	if r == nil {
		return nil, fmt.Errorf("%w: Connector SDK state reader is not open", qurl.ErrAgentStateContinuity)
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if err := r.validateContinuityLocked(); err != nil {
		return nil, err
	}
	state, loadErr := r.state.LoadAgentState(ctx)
	continuityErr := r.validateContinuityLocked()
	if (loadErr != nil || continuityErr != nil) && state != nil {
		*state = qurl.AgentState{}
		state = nil
	}
	return state, errors.Join(loadErr, continuityErr)
}

func (r *SDKStateReader) validateContinuityLocked() error {
	if r == nil || r.state == nil || r.namespace == nil {
		return fmt.Errorf("%w: Connector SDK state reader is not open", qurl.ErrAgentStateContinuity)
	}
	if err := r.namespace.ValidateCurrent(); err != nil {
		return fmt.Errorf("%w: validate Connector state namespace: %w", qurl.ErrAgentStateContinuity, err)
	}
	return nil
}

// Close releases qurl-go's read-only descriptor and then the containing
// Connector namespace. It is idempotent and preserves continuity/close errors.
func (r *SDKStateReader) Close() error {
	if r == nil {
		return nil
	}
	r.closeOnce.Do(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		var beforeErr error
		if r.namespace != nil {
			beforeErr = r.namespace.ValidateCurrent()
			if beforeErr != nil {
				beforeErr = fmt.Errorf("%w: validate Connector state namespace before reader close: %w", qurl.ErrAgentStateContinuity, beforeErr)
			}
		}
		var readerCloseErr error
		if r.state != nil {
			readerCloseErr = r.state.Close()
		}
		var afterErr error
		if r.namespace != nil {
			afterErr = r.namespace.ValidateCurrent()
			if afterErr != nil {
				afterErr = fmt.Errorf("%w: validate Connector state namespace after reader close: %w", qurl.ErrAgentStateContinuity, afterErr)
			}
		}
		var namespaceCloseErr error
		if r.namespace != nil {
			namespaceCloseErr = r.namespace.Close()
		}
		r.closeErr = errors.Join(readerCloseErr, beforeErr, afterErr, namespaceCloseErr)
		r.state = nil
		r.namespace = nil
	})
	return r.closeErr
}

// legacyStateArtifactNames lists every pre-native-runtime state artifact whose
// presence blocks the greenfield cutover. Consumed by both the exported
// os-based LegacyArtifacts and the pinned-namespace legacyArtifactsInNamespace
// so the reject-list has a single source of truth.
func legacyStateArtifactNames() []string {
	return []string{
		AgentIDFile,
		PrivateKeyFile,
		PublicKeyFile,
		SealedPrivateKeyFile,
		"registration_refresh",
		"tunnel_identities.json",
		filepath.Join("etc", "config.toml"),
		filepath.Join("etc", "server.toml"),
	}
}

// LegacyArtifacts returns every pre-native-runtime state artifact present in
// dir. The greenfield cutover deliberately does not migrate split key/TOML
// state: an in-place migration could accidentally bind a new device credential
// to an old or incomplete development identity.
func LegacyArtifacts(dir string) ([]string, error) {
	dir = ResolveDir(dir)
	candidates := legacyStateArtifactNames()
	found := make([]string, 0, len(candidates))
	for _, name := range candidates {
		_, err := os.Lstat(filepath.Join(dir, name))
		switch {
		case err == nil:
			found = append(found, name)
		case errors.Is(err, os.ErrNotExist):
			continue
		default:
			return nil, fmt.Errorf("inspect legacy agent state %s: %w", name, err)
		}
	}
	return found, nil
}

// NewSDKStore constructs the explicit qurl-go local store selected by
// LAYERV_KEY_PROVIDER and returns its process-lifetime owner. It rejects legacy
// and conflicting native state before constructing any provider. The caller
// must Close every successful result after every client/runtime use has ended.
// configuredAgentID is optional; when present it pins a sealed envelope to the
// same identity passed to qurl.WithAgentRuntimeIdentity.
func NewSDKStore(dir, configuredAgentID string) (_ *SDKStore, retErr error) {
	dir = ResolveDir(dir)
	// Ensure the resolved directory exists at exactly 0700 before handing it to
	// the pinned-filesystem layer, which fail-closed rejects a looser pre-existing
	// mode instead of tightening it.
	if err := EnsureDirMode(dir); err != nil {
		return nil, fmt.Errorf("prepare native agent state directory: %w", err)
	}
	namespace, err := prepareNativeStateDir(dir)
	if err != nil {
		return nil, fmt.Errorf("prepare native agent state directory: %w", err)
	}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, namespace.Close())
		}
	}()

	providerName, err := validateSDKStoreLayoutInNamespace(namespace)
	if err != nil {
		return nil, err
	}
	// The pinned qurl-go dependency writes both plaintext and sealed envelopes
	// through its protected-ACL Windows pinned-state implementation.
	// Connector-owned refresh markers, session journals, locks, and identity-
	// cache files use internal/pinnedfs. No production identity or session-state
	// writer uses plain pathname creation inside this protected directory.
	if providerName == KeyProviderFile {
		store, err := qurl.OpenFileAgentState(filepath.Join(dir, AgentStateFile))
		if err != nil {
			return nil, fmt.Errorf("initialize plaintext agent state: %w", err)
		}
		return finishSDKStore(namespace, store, store)
	}

	provider, err := keyProviderForName(providerName)
	if err != nil {
		return nil, fmt.Errorf("initialize %s state key wrapper: %w", providerName, err)
	}
	wrapper := &sdkStateKeyWrapper{provider: provider}
	opts := sealedAgentIDOptions(configuredAgentID)
	store, err := qurl.NewSealedFileAgentState(
		filepath.Join(dir, SealedAgentStateFile),
		providerName,
		wrapper,
		opts...,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize sealed agent state: %w", err)
	}
	return finishSDKStore(namespace, store, store)
}

func validateSDKStoreLayoutInNamespace(namespace *pinnedfs.Directory) (string, error) {
	legacy, err := legacyArtifactsInNamespace(namespace)
	if err != nil {
		return "", err
	}
	if len(legacy) != 0 {
		return "", fmt.Errorf("legacy pre-native agent state found in %s (%s); this greenfield cutover does not migrate split key/TOML state: stop the Connector, clear the state directory, and enroll again", namespace.Path(), strings.Join(legacy, ", "))
	}
	providerName, err := selectedKeyProviderName()
	if err != nil {
		return "", err
	}
	fileStateExists, err := pathExistsInNamespace(namespace, AgentStateFile)
	if err != nil {
		return "", err
	}
	sealedStateExists, err := pathExistsInNamespace(namespace, SealedAgentStateFile)
	if err != nil {
		return "", err
	}
	if fileStateExists && sealedStateExists {
		return "", fmt.Errorf("agent state directory contains both %s and %s; exactly one native state envelope is allowed", AgentStateFile, SealedAgentStateFile)
	}
	if providerName == KeyProviderFile && sealedStateExists {
		return "", fmt.Errorf("%s=%s conflicts with existing %s; provider changes are not an in-place migration", EnvKeyProvider, providerName, SealedAgentStateFile)
	}
	if providerName != KeyProviderFile && fileStateExists {
		return "", fmt.Errorf("%s=%s conflicts with existing %s; provider changes are not an in-place migration", EnvKeyProvider, providerName, AgentStateFile)
	}
	return providerName, nil
}

func finishSDKStore(namespace *pinnedfs.Directory, state qurl.AgentStateStore, continuity qurl.AgentStateContinuity) (*SDKStore, error) {
	store := &SDKStore{state: state, continuity: continuity, namespace: namespace}
	if err := store.ValidateContinuity(); err != nil {
		return nil, errors.Join(err, store.Close())
	}
	return store, nil
}

func legacyArtifactsInNamespace(namespace *pinnedfs.Directory) ([]string, error) {
	candidates := legacyStateArtifactNames()
	found := make([]string, 0, len(candidates))
	for _, name := range candidates {
		_, err := namespace.Lstat(name)
		switch {
		case err == nil:
			found = append(found, name)
		case pinnedfs.IsNotExist(err):
			continue
		default:
			return nil, fmt.Errorf("inspect legacy agent state %s: %w", name, err)
		}
	}
	return found, nil
}

func pathExistsInNamespace(namespace *pinnedfs.Directory, name string) (bool, error) {
	_, err := namespace.Lstat(name)
	switch {
	case err == nil:
		return true, nil
	case pinnedfs.IsNotExist(err):
		return false, nil
	default:
		return false, fmt.Errorf("inspect native agent state %s: %w", filepath.Base(name), err)
	}
}

type sdkStateKeyWrapper struct {
	provider KeyProvider
}

func (w *sdkStateKeyWrapper) WrapKey(ctx context.Context, plaintextKey []byte, binding qurl.AgentStateKeyBinding) (qurl.WrappedAgentStateKey, error) {
	if w == nil || isNilKeyProvider(w.provider) {
		return qurl.WrappedAgentStateKey{}, fmt.Errorf("state key provider is nil")
	}
	if len(plaintextKey) != StateDEKSize {
		return qurl.WrappedAgentStateKey{}, fmt.Errorf("state DEK must be %d bytes", StateDEKSize)
	}
	encContext := sdkKeyEncryptionContext(binding)
	providerCtx, cancel := context.WithTimeout(ctx, keyProviderTimeout)
	defer cancel()
	sealed, err := w.provider.Seal(providerCtx, plaintextKey, encContext)
	if err != nil {
		return qurl.WrappedAgentStateKey{}, err
	}
	if sealed.Provider != w.provider.Name() || !reflect.DeepEqual(sealed.EncryptionContext, encContext) {
		return qurl.WrappedAgentStateKey{}, fmt.Errorf("state key provider returned a record outside the requested binding")
	}
	raw, err := json.Marshal(sealed)
	if err != nil {
		return qurl.WrappedAgentStateKey{}, fmt.Errorf("encode wrapped state DEK: %w", err)
	}
	return qurl.WrappedAgentStateKey{
		Version:    wrappedAgentStateKeyVersion,
		Ciphertext: raw,
	}, nil
}

func (w *sdkStateKeyWrapper) UnwrapKey(ctx context.Context, wrapped qurl.WrappedAgentStateKey, binding qurl.AgentStateKeyBinding) ([]byte, error) {
	if w == nil || isNilKeyProvider(w.provider) {
		return nil, fmt.Errorf("state key provider is nil")
	}
	if wrapped.Version != wrappedAgentStateKeyVersion || len(wrapped.Metadata) != 0 {
		return nil, qurl.ErrInvalidWrappedAgentStateKey
	}
	var sealed SealedPrivateKey
	decoder := json.NewDecoder(bytes.NewReader(wrapped.Ciphertext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&sealed); err != nil {
		return nil, qurl.ErrInvalidWrappedAgentStateKey
	}
	if err := rejectTrailingJSON(decoder); err != nil {
		return nil, qurl.ErrInvalidWrappedAgentStateKey
	}
	wantContext := sdkKeyEncryptionContext(binding)
	if sealed.Version != sealedPrivateKeyVersion || sealed.Provider != w.provider.Name() || !reflect.DeepEqual(sealed.EncryptionContext, wantContext) {
		return nil, qurl.ErrInvalidWrappedAgentStateKey
	}
	providerCtx, cancel := context.WithTimeout(ctx, keyProviderTimeout)
	defer cancel()
	plaintext, err := w.provider.Unseal(providerCtx, sealed)
	if err != nil {
		return nil, err
	}
	if len(plaintext) != StateDEKSize {
		scrubBytes(plaintext)
		return nil, fmt.Errorf("state key provider returned %d bytes, want %d", len(plaintext), StateDEKSize)
	}
	return plaintext, nil
}

func sdkKeyEncryptionContext(binding qurl.AgentStateKeyBinding) map[string]string {
	return map[string]string{
		"purpose":          wrappedKeyPurpose + "/" + binding.Purpose,
		"envelope_version": strconv.Itoa(binding.EnvelopeVersion),
		"provider_id":      binding.ProviderID,
		"agent_id":         binding.AgentID,
	}
}

// sealedAgentIDOptions returns the sealed-file-state options that pin the
// expected agent identity when the operator configured one, and no options
// otherwise (greenfield state adopts the persisted identity).
func sealedAgentIDOptions(configuredAgentID string) []qurl.SealedFileAgentStateOption {
	if configuredAgentID == "" {
		return nil
	}
	return []qurl.SealedFileAgentStateOption{qurl.WithExpectedSealedAgentID(configuredAgentID)}
}

func rejectTrailingJSON(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func isNilKeyProvider(provider KeyProvider) bool {
	if provider == nil {
		return true
	}
	v := reflect.ValueOf(provider)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}

// ConfiguredAgentID returns the optional stable identity supplied by the
// operator. qurl-go generates and persists a UUID when it is empty.
func ConfiguredAgentID() string {
	return strings.TrimSpace(os.Getenv(EnvAgentID))
}
