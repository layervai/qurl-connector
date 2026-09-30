package agentstate

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

const (
	tpmRecordKeyID  = "tpm:v1"
	tpmKEKSize      = 32
	tpmMaxBlobBytes = 4 << 10

	// tpmPersistentSRKHandle is the TCG-reserved storage root key handle.
	// Windows provisions an SRK there and does not retain owner authorization,
	// so a transient primary cannot be created under the owner hierarchy.
	tpmPersistentSRKHandle tpm2.TPMHandle = 0x81000001
)

// tpmParent names the storage key a sealed KEK was created under. It is
// persisted in the record so Unseal loads under the same parent Seal used.
type tpmParent byte

const (
	// tpmParentTransientECCSRK is the TCG reference ECC P-256 SRK, recreated
	// deterministically from the owner seed on every use.
	tpmParentTransientECCSRK tpmParent = 1
	// tpmParentPersistentSRK is the SRK already provisioned at
	// tpmPersistentSRKHandle.
	tpmParentPersistentSRK tpmParent = 2
)

// ErrTPMUnavailable reports that this machine has no TPM 2.0 the current user
// can use: no device, no resource manager, no permission, or no usable storage
// root key. Fresh namespaces then use the plaintext file envelope.
var ErrTPMUnavailable = errors.New("TPM 2.0 is unavailable")

type tpmCloser = transport.TPMCloser

// openTPM opens the platform TPM 2.0 resource manager. Tests replace it with a
// simulator.
var openTPM func() (tpmCloser, error) = openSystemTPM

// ErrTPMNotResponding reports a TPM that is present but did not complete an
// operation: a timeout, device I/O failure, or a TPM warning (retry, testing,
// out of memory). Unlike ErrTPMUnavailable it is not a reason to fall back to
// plaintext, because the TPM may answer on the next attempt.
var ErrTPMNotResponding = errors.New("TPM 2.0 is not responding")

// tpmProbeTimeout bounds ProbeTPM, which runs on the path that opens a fresh
// namespace and has no caller context.
var tpmProbeTimeout = 10 * time.Second

var tpmProbe struct {
	sync.Mutex
	done bool
	err  error
}

// ProbeTPM reports whether this process can seal state under the local TPM:
// it opens the TPM, prepares the storage root key, and releases both, within
// tpmProbeTimeout. A nil result or an ErrTPMUnavailable one (no device, no
// permission, no usable storage root key) is structural and cached for the
// process lifetime. An ErrTPMNotResponding result is transient and is not
// cached, so the next call probes again.
func ProbeTPM() error {
	tpmProbe.Lock()
	defer tpmProbe.Unlock()
	if tpmProbe.done {
		return tpmProbe.err
	}
	ctx, cancel := context.WithTimeout(context.Background(), tpmProbeTimeout)
	defer cancel()
	open := openTPM
	_, err := runTPMBounded(ctx, func() (struct{}, error) { return struct{}{}, probeTPMOnce(open) }, nil)
	err = classifyTPMError(err)
	if !errors.Is(err, ErrTPMNotResponding) {
		tpmProbe.err, tpmProbe.done = err, true
	}
	return err
}

func probeTPMOnce(open func() (tpmCloser, error)) (retErr error) {
	tpm, err := open()
	if err != nil {
		return tpmOpenError(err)
	}
	defer func() { retErr = errors.Join(retErr, tpm.Close()) }()
	parent, err := selectTPMParent(tpm)
	if err != nil {
		return err
	}
	return parent.flush(tpm)
}

// tpmOpenError marks a failure to open the device. Missing devices, missing
// permission, and platforms without a TPM are structural; a busy device or a
// resource manager that is still starting (tpmOpenTransient) is not.
func tpmOpenError(err error) error {
	if tpmOpenTransient(err) {
		return fmt.Errorf("%w: open TPM: %w", ErrTPMNotResponding, err)
	}
	return fmt.Errorf("%w: %w", ErrTPMUnavailable, err)
}

// tpmCommandError labels a failed TPM command. A warning or device I/O failure
// is transient and carries ErrTPMNotResponding; any other TPM response (for
// example an integrity failure on a tampered record) stays unclassified,
// because it describes the record rather than the TPM.
func tpmCommandError(label string, err error) error {
	var rc tpm2.TPMRC
	var fmt1 tpm2.TPMFmt1Error
	if (errors.As(err, &rc) && !rc.IsWarning()) || errors.As(err, &fmt1) {
		return fmt.Errorf("%s: %w", label, err)
	}
	return fmt.Errorf("%w: %s: %w", ErrTPMNotResponding, label, err)
}

// classifyTPMError sorts a probe failure into ErrTPMUnavailable (structural:
// retrying cannot help) or ErrTPMNotResponding (transient). Errors already
// carrying either sentinel keep it. A TPM error response is structural unless
// it is a warning; anything else (a deadline, device I/O) is transient.
func classifyTPMError(err error) error {
	if err == nil || errors.Is(err, ErrTPMUnavailable) || errors.Is(err, ErrTPMNotResponding) {
		return err
	}
	var rc tpm2.TPMRC
	if errors.As(err, &rc) && !rc.IsWarning() {
		return fmt.Errorf("%w: %w", ErrTPMUnavailable, err)
	}
	var fmt1 tpm2.TPMFmt1Error
	if errors.As(err, &fmt1) {
		return fmt.Errorf("%w: %w", ErrTPMUnavailable, err)
	}
	return fmt.Errorf("%w: %w", ErrTPMNotResponding, err)
}

// tpmKeyProvider seals the qurl-go state DEK to this machine's TPM. The TPM
// holds a random 32-byte KEK as a sealed data object under the storage root
// key (fixedTPM, fixedParent, noDA, empty authorization); the DEK itself is
// AES-256-GCM encrypted under that KEK with the envelope binding as AAD. The
// record is useless off this TPM, and the provider needs no key material from
// the environment, so a credential-free managed daemon can open it.
type tpmKeyProvider struct{}

func newTPMKeyProvider() (KeyProvider, error) { return tpmKeyProvider{}, nil }

func (tpmKeyProvider) Name() string { return KeyProviderTPM }

func (p tpmKeyProvider) Seal(ctx context.Context, plaintext []byte, encContext map[string]string) (SealedPrivateKey, error) {
	if err := ctx.Err(); err != nil {
		return SealedPrivateKey{}, err
	}
	plaintext = append([]byte(nil), plaintext...)
	open := openTPM
	return runTPMBounded(ctx, func() (SealedPrivateKey, error) {
		defer scrubBytes(plaintext)
		return p.sealWithTPM(open, plaintext, encContext)
	}, nil)
}

func (p tpmKeyProvider) sealWithTPM(open func() (tpmCloser, error), plaintext []byte, encContext map[string]string) (_ SealedPrivateKey, retErr error) {
	aad, err := encryptionContextAAD(encContext)
	if err != nil {
		return SealedPrivateKey{}, err
	}
	kek := make([]byte, tpmKEKSize)
	defer scrubBytes(kek)
	if _, err := io.ReadFull(rand.Reader, kek); err != nil {
		return SealedPrivateKey{}, fmt.Errorf("generate TPM KEK: %w", err)
	}

	tpm, err := open()
	if err != nil {
		return SealedPrivateKey{}, tpmOpenError(err)
	}
	defer func() { retErr = errors.Join(retErr, tpm.Close()) }()
	parent, err := selectTPMParent(tpm)
	if err != nil {
		return SealedPrivateKey{}, classifyTPMError(err)
	}
	defer func() { retErr = errors.Join(retErr, parent.flush(tpm)) }()

	created, err := tpm2.Create{
		ParentHandle: tpm2.AuthHandle{
			Handle: parent.handle,
			Name:   parent.name,
			// Salted to the parent and encrypting the command parameter, so the
			// KEK never crosses the TPM bus in the clear.
			Auth: tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptIn), tpm2.Salted(parent.handle, parent.public)),
		},
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: kek}),
			},
		},
		InPublic: tpm2.New2B(tpmSealedKEKTemplate()),
	}.Execute(tpm)
	if err != nil {
		return SealedPrivateKey{}, tpmCommandError("seal KEK to TPM", err)
	}

	aead, err := tpmAEAD(kek)
	if err != nil {
		return SealedPrivateKey{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return SealedPrivateKey{}, fmt.Errorf("generate TPM record nonce: %w", err)
	}
	record := tpmRecord{
		parent:     parent.kind,
		parentName: parent.name.Buffer,
		public:     tpm2.Marshal(created.OutPublic),
		private:    tpm2.Marshal(created.OutPrivate),
		sealed:     aead.Seal(nonce, nonce, plaintext, aad),
	}
	raw, err := record.marshal()
	if err != nil {
		return SealedPrivateKey{}, err
	}
	return sealedCiphertextRecord(p.Name(), tpmRecordKeyID, raw, encContext), nil
}

func (p tpmKeyProvider) Unseal(ctx context.Context, sealed SealedPrivateKey) ([]byte, error) {
	if sealed.Provider != p.Name() {
		return nil, fmt.Errorf("sealed key provider %q does not match selected provider %q", sealed.Provider, p.Name())
	}
	if sealed.KeyID != tpmRecordKeyID {
		return nil, fmt.Errorf("sealed TPM key id %q is unsupported", sealed.KeyID)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := sealedCiphertextBytes(sealed)
	if err != nil {
		return nil, err
	}
	record, err := parseTPMRecord(raw)
	if err != nil {
		return nil, err
	}
	aad, err := encryptionContextAAD(sealed.EncryptionContext)
	if err != nil {
		return nil, err
	}
	public, err := tpm2.Unmarshal[tpm2.TPM2BPublic](record.public)
	if err != nil {
		return nil, fmt.Errorf("decode TPM sealed object public area: %w", err)
	}
	private, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](record.private)
	if err != nil {
		return nil, fmt.Errorf("decode TPM sealed object private area: %w", err)
	}
	open := openTPM
	return runTPMBounded(ctx, func() ([]byte, error) {
		return unsealWithTPM(open, record, public, private, aad)
	}, scrubBytes)
}

func unsealWithTPM(open func() (tpmCloser, error), record tpmRecord, public *tpm2.TPM2BPublic, private *tpm2.TPM2BPrivate, aad []byte) (_ []byte, retErr error) {
	tpm, err := open()
	if err != nil {
		return nil, tpmOpenError(err)
	}
	defer func() { retErr = errors.Join(retErr, tpm.Close()) }()
	parent, err := openTPMParent(tpm, record.parent)
	if err != nil {
		return nil, classifyTPMError(err)
	}
	defer func() { retErr = errors.Join(retErr, parent.flush(tpm)) }()
	if !bytes.Equal(parent.name.Buffer, record.parentName) {
		return nil, errors.New("TPM storage root key does not match the one this state was sealed under; the TPM was cleared or this state belongs to another machine")
	}

	loaded, err := tpm2.Load{
		ParentHandle: tpm2.AuthHandle{Handle: parent.handle, Name: parent.name, Auth: tpm2.PasswordAuth(nil)},
		InPrivate:    *private,
		InPublic:     *public,
	}.Execute(tpm)
	if err != nil {
		return nil, tpmCommandError("load TPM sealed KEK", err)
	}
	defer func() { retErr = errors.Join(retErr, flushTPMHandle(tpm, loaded.ObjectHandle)) }()

	unsealed, err := tpm2.Unseal{
		ItemHandle: tpm2.AuthHandle{
			Handle: loaded.ObjectHandle,
			Name:   loaded.Name,
			Auth:   tpm2.HMAC(tpm2.TPMAlgSHA256, 16, tpm2.AESEncryption(128, tpm2.EncryptOut), tpm2.Salted(parent.handle, parent.public)),
		},
	}.Execute(tpm)
	if err != nil {
		return nil, tpmCommandError("unseal TPM KEK", err)
	}
	kek := unsealed.OutData.Buffer
	defer scrubBytes(kek)
	if len(kek) != tpmKEKSize {
		return nil, fmt.Errorf("TPM returned a %d-byte KEK, want %d", len(kek), tpmKEKSize)
	}
	aead, err := tpmAEAD(kek)
	if err != nil {
		return nil, err
	}
	if len(record.sealed) < aead.NonceSize()+aead.Overhead() {
		return nil, errors.New("TPM record ciphertext is too short")
	}
	plaintext, err := aead.Open(nil, record.sealed[:aead.NonceSize()], record.sealed[aead.NonceSize():], aad)
	if err != nil {
		return nil, fmt.Errorf("TPM record AES-GCM authentication failed: %w", err)
	}
	return plaintext, nil
}

// tpmAbandoned tracks TPM operations whose caller gave up while they were
// still blocked in the device. For tpmWedgeBackoff after an abandonment the
// TPM is presumed wedged and new operations fail fast instead of each parking
// another goroutine and descriptor behind it. The gate reopens when the
// abandoned operations finish or the backoff elapses, whichever is first, so a
// TPM that recovers is used again. Callers waiting when it reopens are all
// admitted; against a TPM that is still wedged each of them is abandoned in
// turn and closes the gate for another period, so parked operations grow with
// caller concurrency per period rather than with every retry.
var tpmAbandoned struct {
	sync.Mutex
	count int
	last  time.Time
}

var tpmWedgeBackoff = 30 * time.Second

// runTPMBounded runs one TPM round trip under ctx. TPM commands are blocking
// device I/O with no deadline of their own, so a wedged TPM or a long command
// queued ahead of this one would otherwise hang the caller past the key
// provider timeout. On expiry the caller gets ErrTPMNotResponding while op
// finishes in the background on its own transport; discard then scrubs a late
// result. While a recent abandonment is outstanding, later calls fail
// immediately; see tpmAbandoned.
func runTPMBounded[T any](ctx context.Context, op func() (T, error), discard func(T)) (T, error) {
	var zero T
	tpmAbandoned.Lock()
	wedged := tpmAbandoned.count > 0 && time.Since(tpmAbandoned.last) < tpmWedgeBackoff
	tpmAbandoned.Unlock()
	if wedged {
		return zero, fmt.Errorf("%w: an earlier TPM operation has not returned", ErrTPMNotResponding)
	}
	type result struct {
		value T
		err   error
	}
	var mu sync.Mutex
	abandoned := false
	done := make(chan result, 1)
	go func() {
		value, err := op()
		mu.Lock()
		defer mu.Unlock()
		if !abandoned {
			done <- result{value: value, err: err}
			return
		}
		if err == nil && discard != nil {
			discard(value)
		}
		tpmAbandoned.Lock()
		tpmAbandoned.count--
		tpmAbandoned.Unlock()
	}()
	select {
	case r := <-done:
		return r.value, r.err
	case <-ctx.Done():
		mu.Lock()
		defer mu.Unlock()
		select {
		case r := <-done:
			return r.value, r.err
		default:
		}
		abandoned = true
		tpmAbandoned.Lock()
		tpmAbandoned.count++
		tpmAbandoned.last = time.Now()
		tpmAbandoned.Unlock()
		return zero, fmt.Errorf("%w: operation abandoned: %w", ErrTPMNotResponding, ctx.Err())
	}
}

// tpmECCSRKTemplate is the TCG reference ECC P-256 SRK template (TCG TPM v2.0
// Provisioning Guidance). The recreated SRK's Name, which every sealed record
// persists, is derived from these exact bytes, so the template is this
// package's data rather than a dependency's: a library revising its copy must
// not make every existing record look like it came from another machine.
// Changing this literal requires a new tpmParent kind.
func tpmECCSRKTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			Restricted:          true,
			Decrypt:             true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			Symmetric: tpm2.TPMTSymDefObject{
				Algorithm: tpm2.TPMAlgAES,
				KeyBits:   tpm2.NewTPMUSymKeyBits(tpm2.TPMAlgAES, tpm2.TPMKeyBits(128)),
				Mode:      tpm2.NewTPMUSymMode(tpm2.TPMAlgAES, tpm2.TPMAlgCFB),
			},
			CurveID: tpm2.TPMECCNistP256,
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgECC, &tpm2.TPMSECCPoint{
			X: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
			Y: tpm2.TPM2BECCParameter{Buffer: make([]byte, 32)},
		}),
	}
}

// tpmSealedKEKTemplate is a keyed-hash data object that only this TPM can
// load, only under its original parent, that never counts toward dictionary-
// attack lockout, and whose empty user authorization is proved through the
// caller's session.
func tpmSealedKEKTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:     true,
			FixedParent:  true,
			UserWithAuth: true,
			NoDA:         true,
		},
	}
}

func tpmAEAD(kek []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, fmt.Errorf("initialize TPM record AES-256: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize TPM record AES-GCM: %w", err)
	}
	return aead, nil
}

// tpmParentKey is a loaded storage parent. flush releases a transient one and
// leaves a persistent one in place.
type tpmParentKey struct {
	kind      tpmParent
	handle    tpm2.TPMHandle
	name      tpm2.TPM2BName
	public    tpm2.TPMTPublic
	transient bool
}

func (p tpmParentKey) flush(tpm transport.TPM) error {
	if !p.transient {
		return nil
	}
	return flushTPMHandle(tpm, p.handle)
}

// selectTPMParent prefers the deterministic transient ECC SRK and falls back
// to the provisioned persistent SRK where owner authorization is not empty.
// tpmParentMemo remembers which storage parent worked, so a TPM whose owner
// hierarchy rejects the empty authorization sees that failed attempt at most
// once per process rather than on every seal.
var tpmParentMemo struct {
	sync.Mutex
	kind tpmParent
}

// selectTPMParent returns the storage parent to seal under: the one that
// worked before in this process, otherwise the platform's preferred order.
// Where owner authorization is not empty (Windows), the provisioned SRK is
// tried first so the owner hierarchy is not asked for an authorization it
// will refuse.
func selectTPMParent(tpm transport.TPM) (tpmParentKey, error) {
	tpmParentMemo.Lock()
	remembered := tpmParentMemo.kind
	tpmParentMemo.Unlock()
	order := tpmParentOrder
	if remembered != 0 {
		order = []tpmParent{remembered}
		for _, kind := range tpmParentOrder {
			if kind != remembered {
				order = append(order, kind)
			}
		}
	}
	var errs []error
	transient := false
	for _, kind := range order {
		parent, err := openTPMParent(tpm, kind)
		if err == nil {
			tpmParentMemo.Lock()
			tpmParentMemo.kind = kind
			tpmParentMemo.Unlock()
			return parent, nil
		}
		transient = transient || errors.Is(classifyTPMError(err), ErrTPMNotResponding)
		errs = append(errs, fmt.Errorf("%s: %w", kind, err))
	}
	// Classify here, per attempt, rather than letting a caller run errors.As
	// over the join: when one parent failed transiently and the other
	// structurally, the first match in the tree would decide, and a transient
	// failure read as structural is cached as "no TPM" for the process. Any
	// transient attempt makes the whole failure transient.
	sentinel := ErrTPMUnavailable
	if transient {
		sentinel = ErrTPMNotResponding
	}
	return tpmParentKey{}, fmt.Errorf("%w: no usable storage root key: %w", sentinel, errors.Join(errs...))
}

func (k tpmParent) String() string {
	switch k {
	case tpmParentTransientECCSRK:
		return "ECC SRK"
	case tpmParentPersistentSRK:
		return "persistent SRK"
	default:
		return fmt.Sprintf("parent %d", byte(k))
	}
}

func openTPMParent(tpm transport.TPM, kind tpmParent) (tpmParentKey, error) {
	switch kind {
	case tpmParentTransientECCSRK:
		created, err := tpm2.CreatePrimary{
			PrimaryHandle: tpm2.TPMRHOwner,
			InPublic:      tpm2.New2B(tpmECCSRKTemplate()),
		}.Execute(tpm)
		if err != nil {
			return tpmParentKey{}, err
		}
		public, err := created.OutPublic.Contents()
		if err != nil {
			return tpmParentKey{}, errors.Join(fmt.Errorf("decode SRK public area: %w", err), flushTPMHandle(tpm, created.ObjectHandle))
		}
		return tpmParentKey{kind: kind, handle: created.ObjectHandle, name: created.Name, public: *public, transient: true}, nil
	case tpmParentPersistentSRK:
		read, err := tpm2.ReadPublic{ObjectHandle: tpmPersistentSRKHandle}.Execute(tpm)
		if err != nil {
			return tpmParentKey{}, err
		}
		public, err := read.OutPublic.Contents()
		if err != nil {
			return tpmParentKey{}, fmt.Errorf("decode persistent SRK public area: %w", err)
		}
		attrs := public.ObjectAttributes
		if !attrs.FixedTPM || !attrs.FixedParent || !attrs.Restricted || !attrs.Decrypt || attrs.SignEncrypt {
			return tpmParentKey{}, errors.New("persistent SRK is not a restricted storage key")
		}
		return tpmParentKey{kind: kind, handle: tpmPersistentSRKHandle, name: read.Name, public: *public}, nil
	default:
		return tpmParentKey{}, fmt.Errorf("unsupported TPM parent %d", kind)
	}
}

func flushTPMHandle(tpm transport.TPM, handle tpm2.TPMHandle) error {
	if _, err := (tpm2.FlushContext{FlushHandle: handle}).Execute(tpm); err != nil {
		return fmt.Errorf("flush TPM handle %#x: %w", uint32(handle), err)
	}
	return nil
}

// tpmRecord is the provider-owned ciphertext inside SealedPrivateKey:
//
//	parent(1) | len(2) parentName | len(2) public | len(2) private | nonce||AES-GCM
//
// Lengths are big-endian. The TPM structures are their TPM2B wire encodings.
type tpmRecord struct {
	parent     tpmParent
	parentName []byte
	public     []byte
	private    []byte
	sealed     []byte
}

func (r tpmRecord) marshal() ([]byte, error) {
	var out bytes.Buffer
	out.WriteByte(byte(r.parent))
	if len(r.sealed) == 0 {
		return nil, errors.New("TPM record has no ciphertext")
	}
	for _, field := range [][]byte{r.parentName, r.public, r.private} {
		if len(field) == 0 || len(field) > tpmMaxBlobBytes {
			return nil, fmt.Errorf("TPM record field has %d bytes", len(field))
		}
		_ = binary.Write(&out, binary.BigEndian, uint16(len(field))) //nolint:gosec // bounded by tpmMaxBlobBytes above.
		out.Write(field)
	}
	out.Write(r.sealed)
	return out.Bytes(), nil
}

func parseTPMRecord(raw []byte) (tpmRecord, error) {
	invalid := errors.New("TPM record is malformed")
	if len(raw) < 1 {
		return tpmRecord{}, invalid
	}
	record := tpmRecord{parent: tpmParent(raw[0])}
	if record.parent != tpmParentTransientECCSRK && record.parent != tpmParentPersistentSRK {
		return tpmRecord{}, invalid
	}
	rest := raw[1:]
	fields := []*[]byte{&record.parentName, &record.public, &record.private}
	for _, field := range fields {
		if len(rest) < 2 {
			return tpmRecord{}, invalid
		}
		size := int(binary.BigEndian.Uint16(rest))
		rest = rest[2:]
		if size == 0 || size > tpmMaxBlobBytes || len(rest) < size {
			return tpmRecord{}, invalid
		}
		*field = rest[:size:size]
		rest = rest[size:]
	}
	if len(rest) == 0 {
		return tpmRecord{}, invalid
	}
	record.sealed = rest
	return record, nil
}
