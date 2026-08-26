package replica

import (
	"context"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
)

// fixedReader returns a deterministic byte stream so the
// random-fallback branch is testable.
func fixedReader(out []byte) func(b []byte) (int, error) {
	return func(b []byte) (int, error) {
		n := copy(b, out)
		return n, nil
	}
}

func TestResolve_EnvBranch(t *testing.T) {
	r := &Resolver{
		Env: map[string]string{EnvReplicaID: "  REPLICA-7  "},
	}
	got, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "replica-7" {
		t.Errorf("discriminator = %q, want %q (normalized lower-case, trimmed)", got, "replica-7")
	}
	if meta.Source != SourceEnv {
		t.Errorf("Source = %q, want %q", meta.Source, SourceEnv)
	}
	if meta.Warning != "" {
		t.Errorf("Warning = %q, want empty for canonical branch", meta.Warning)
	}
}

func TestResolve_EnvBlankFallsThrough(t *testing.T) {
	r := &Resolver{
		Env: map[string]string{
			EnvReplicaID: "   ",
		},
		// Short hostname so the post-normalize value is the literal
		// passthrough (no hash-suffix truncation needed).
		Hostname: func() (string, error) { return "host-7", nil },
	}
	got, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "host-7" {
		t.Errorf("discriminator = %q, want %q (short hostname passthrough)", got, "host-7")
	}
	if meta.Source != SourceHostname {
		t.Errorf("Source = %q, want %q (whitespace-only env must fall through to hostname before machine-id)", meta.Source, SourceHostname)
	}
	if warnings := r.Warnings(); len(warnings) != 0 {
		t.Errorf("Warnings() = %v, want none for whitespace-only env", warnings)
	}
}

func TestResolve_EnvNormalizeEmptyWarnsAndFallsThrough(t *testing.T) {
	r := &Resolver{
		Env: map[string]string{
			EnvReplicaID: "!!!",
		},
		Hostname: func() (string, error) { return "host-7", nil },
	}
	got, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "host-7" {
		t.Errorf("discriminator = %q, want hostname fallback", got)
	}
	if meta.Source != SourceHostname {
		t.Errorf("Source = %q, want %q", meta.Source, SourceHostname)
	}
	warnings := r.Warnings()
	if len(warnings) != 1 || !strings.Contains(warnings[0], EnvReplicaID) {
		t.Fatalf("Warnings() = %v, want one %s discard warning", warnings, EnvReplicaID)
	}
}

func TestResolve_ECSBranch_ExtractsTaskUUID(t *testing.T) {
	// A real ECS task UUID is longer than MaxDiscriminatorLen, so
	// the Normalize call routes through the hash-suffix truncation
	// branch. Assert the SHAPE (length + prefix matches the first
	// 7 hex chars of the UUID) rather than the literal hash, since
	// hash bytes are an implementation detail of Normalize.
	const arn = `arn:aws:ecs:us-east-2:111122223333:task/example-service/abcdef0123456789cafebabe`
	body := `{"TaskARN": "` + arn + `", "Cluster": "qurl-fileviewer-v2"}`
	r := &Resolver{
		Env: map[string]string{
			EnvECSContainerMetadataURI: "http://169.254.170.2/v4/abc",
		},
		ECS: func(ctx context.Context, endpoint string) (string, error) {
			return body, nil
		},
	}
	got, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(got) != MaxDiscriminatorLen {
		t.Errorf("discriminator length = %d, want %d (UUID-shaped input goes through hash-suffix truncation)", len(got), MaxDiscriminatorLen)
	}
	if !strings.HasPrefix(got, "abcdef0") {
		t.Errorf("discriminator = %q, want prefix %q (first 7 chars of the task UUID)", got, "abcdef0")
	}
	if meta.Source != SourceECS {
		t.Errorf("Source = %q, want %q", meta.Source, SourceECS)
	}
	if !strings.Contains(meta.Raw, "abcdef0123456789cafebabe") {
		t.Errorf("meta.Raw = %q, want full task UUID", meta.Raw)
	}
}

func TestResolve_ECSEndpoint_EmptyFallsThrough(t *testing.T) {
	r := &Resolver{
		Env: map[string]string{
			EnvECSContainerMetadataURI: "   ",
		},
		Hostname: func() (string, error) { return "host-fallthrough", nil },
	}
	_, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if meta.Source != SourceHostname {
		t.Errorf("Source = %q, want %q (whitespace-only ECS endpoint must fall through to hostname)", meta.Source, SourceHostname)
	}
}

func TestResolve_ECSMetadataMissingUUIDRecordsSoftError(t *testing.T) {
	r := &Resolver{
		Env: map[string]string{
			EnvECSContainerMetadataURI: "http://169.254.170.2/v4/abc",
		},
		ECS: func(ctx context.Context, endpoint string) (string, error) {
			return `{"TaskARN":""}`, nil
		},
		Hostname: func() (string, error) { return "host-fallthrough", nil },
	}
	got, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "host-fallthrough" {
		t.Errorf("discriminator = %q, want hostname fallback", got)
	}
	if meta.Source != SourceHostname {
		t.Errorf("Source = %q, want %q", meta.Source, SourceHostname)
	}
	if softErrs := r.Errors(); softErrs == nil || !strings.Contains(softErrs.Error(), "TaskARN") {
		t.Fatalf("Errors() = %v, want unusable ECS metadata soft error", softErrs)
	}
}

func TestResolverDiagnosticsConcurrentWithResolve(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	r := &Resolver{
		Env: map[string]string{
			EnvReplicaID:               "!!!",
			EnvECSContainerMetadataURI: "http://169.254.170.2/v4/abc",
		},
		ECS: func(ctx context.Context, endpoint string) (string, error) {
			close(started)
			<-release
			return `{"TaskARN":""}`, nil
		},
		Hostname: func() (string, error) { return "host-fallthrough", nil },
	}

	resolveDone := make(chan error, 1)
	go func() {
		_, _, err := r.Resolve(context.Background())
		resolveDone <- err
	}()
	<-started

	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			select {
			case <-stop:
				return
			default:
				_ = r.Errors()
				_ = r.Warnings()
			}
		}
	}()

	close(release)
	if err := <-resolveDone; err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	close(stop)
	<-readerDone

	if softErrs := r.Errors(); softErrs == nil || !strings.Contains(softErrs.Error(), "TaskARN") {
		t.Fatalf("Errors() = %v, want ECS soft error after concurrent read", softErrs)
	}
	if warnings := r.Warnings(); len(warnings) != 1 || !strings.Contains(warnings[0], EnvReplicaID) {
		t.Fatalf("Warnings() = %v, want %s discard warning", warnings, EnvReplicaID)
	}
}

func TestResolve_HostnamePreferredOverMachineID(t *testing.T) {
	// Hostname now ranks ABOVE machine-id (the cr-1 finding): on
	// multi-replica-per-host orchestrators (k8s pods, docker compose
	// --scale=N) /etc/machine-id is shared and would re-introduce the
	// FRP NewProxy collision the salt exists to avoid.
	r := &Resolver{
		Env:      map[string]string{},
		Hostname: func() (string, error) { return "pod-abc-7", nil },
		Machine:  func() (string, error) { return "host-shared-mid", nil },
	}
	got, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "pod-abc-7" {
		t.Errorf("discriminator = %q, want hostname-derived (hostname preferred over machine-id)", got)
	}
	if meta.Source != SourceHostname {
		t.Errorf("Source = %q, want %q", meta.Source, SourceHostname)
	}
}

func TestResolve_MachineIDBranch(t *testing.T) {
	// machine-id is a stable host identifier. The resolver hashes it
	// before normalization so the raw value is never rendered into FRP
	// proxy names or boot logs.
	const machineID = "abcdef0123456789"
	r := &Resolver{
		Env:      map[string]string{},
		Hostname: func() (string, error) { return "", errors.New("no hostname") },
		Machine:  func() (string, error) { return machineID, nil },
	}
	got, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	want := shortHash(machineID, MaxDiscriminatorLen)
	if got != want {
		t.Errorf("discriminator = %q, want opaque hash prefix %q", got, want)
	}
	if strings.Contains(got, "abcdef") {
		t.Errorf("discriminator = %q leaks raw machine-id prefix", got)
	}
	if meta.Source != SourceMachineID {
		t.Errorf("Source = %q, want %q (only after hostname fails)", meta.Source, SourceMachineID)
	}
	if meta.Raw != "" {
		t.Errorf("meta.Raw = %q, want empty so machine-id is not logged", meta.Raw)
	}
}

func TestResolve_RandomFallback_LogsWarning(t *testing.T) {
	r := &Resolver{
		Env:      map[string]string{},
		Hostname: func() (string, error) { return "", errors.New("no hostname") },
		Machine:  func() (string, error) { return "", errors.New("no machine-id") },
		RandRead: fixedReader([]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}),
	}
	got, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if !strings.HasPrefix(got, "deadbeefcafe") {
		t.Errorf("discriminator = %q, want deterministic random prefix", got)
	}
	if meta.Source != SourceRandomFallback {
		t.Errorf("Source = %q, want %q", meta.Source, SourceRandomFallback)
	}
	if meta.Warning == "" {
		t.Errorf("Warning empty; expected non-empty for random fallback")
	}
}

func TestResolve_RandomFallbackShortReadUsesNoEntropy(t *testing.T) {
	r := &Resolver{
		Env:      map[string]string{},
		Hostname: func() (string, error) { return "", errors.New("no hostname") },
		Machine:  func() (string, error) { return "", errors.New("no machine-id") },
		RandRead: func(b []byte) (int, error) {
			b[0] = 0xde
			return 1, nil
		},
	}
	got, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "no-entropy" {
		t.Errorf("discriminator = %q, want no-entropy sentinel", got)
	}
	if meta.Source != SourceRandomFallback {
		t.Errorf("Source = %q, want %q", meta.Source, SourceRandomFallback)
	}
	if softErrs := r.Errors(); softErrs == nil || !errors.Is(softErrs, io.ErrUnexpectedEOF) {
		t.Fatalf("Errors() = %v, want io.ErrUnexpectedEOF", softErrs)
	}
}

// Determinism: two Resolve calls on the same Resolver return the
// same value. The sync.Once latch is what carries this — without it
// the managed FRP session's per-cycle re-render would produce a NEW salt
// every loop and the registrations would flap.
func TestResolve_IdempotentWithinResolver(t *testing.T) {
	r := &Resolver{
		Env:      map[string]string{},
		Hostname: func() (string, error) { return "host-once", nil },
	}
	got1, _, _ := r.Resolve(context.Background())
	got2, _, _ := r.Resolve(context.Background())
	if got1 != got2 {
		t.Errorf("Resolve not idempotent: %q vs %q", got1, got2)
	}
}

// Process-scoping: two Resolver instances are INDEPENDENT (the cache
// is on the struct, not package-level). Tests need this — otherwise
// the first test's resolution would taint every subsequent test.
func TestResolve_PerResolverCache(t *testing.T) {
	a := &Resolver{
		Env:      map[string]string{},
		Hostname: func() (string, error) { return "host-a", nil },
	}
	b := &Resolver{
		Env:      map[string]string{},
		Hostname: func() (string, error) { return "host-b", nil },
	}
	gotA, _, _ := a.Resolve(context.Background())
	gotB, _, _ := b.Resolve(context.Background())
	if gotA == gotB {
		t.Errorf("two Resolver instances resolved to the same value (%q); cache MUST be per-Resolver, not package-level", gotA)
	}
	if gotA != "host-a" {
		t.Errorf("a discriminator = %q, want host-a", gotA)
	}
	if gotB != "host-b" {
		t.Errorf("b discriminator = %q, want host-b", gotB)
	}
}

func TestExtractECSTaskUUID(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "well-formed",
			body: `{"TaskARN":"arn:aws:ecs:us-east-2:1:task/cluster/uuid-here"}`,
			want: "uuid-here",
		},
		{
			name: "trailing slash",
			body: `{"TaskARN":"arn:aws:ecs:us-east-2:1:task/cluster/uuid-here/"}`,
			want: "uuid-here",
		},
		{
			name: "malformed no slash",
			body: `{"TaskARN":"justastring"}`,
			want: "",
		},
		{
			name: "empty arn",
			body: `{"TaskARN":""}`,
			want: "",
		},
		{
			name: "bad json",
			body: `not json`,
			want: "",
		},
		{
			name: "missing field",
			body: `{"OtherField":"x"}`,
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := extractECSTaskUUID(tc.body); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	// Cases that fit within MaxDiscriminatorLen pass through cleanly.
	shortCases := []struct {
		in, want string
	}{
		{"REPLICA-7", "replica-7"},
		{"  trim  ", "trim"},
		{"a/b/c", "abc"},
		{"a_b_c", "abc"},
		{"!!!", ""},
		{"", ""},
		// Hyphen-collapse + leading/trailing strip: the cr-finding
		// that a raw "-foo--bar-" was producing "-foo--bar-".
		{"-foo--bar-", "foo-bar"},
		{"---hello---world---", "hello-world"},
		// Mixed glyphs: filter MAY leave a trailing hyphen post-
		// filter; the post-collapse trim must scrub it.
		{"abc-!!!", "abc"},
		// Only ASCII digits are allowed. unicode.IsDigit admits
		// non-DNS-safe glyphs such as Arabic-Indic digits, which
		// violates the documented [0-9a-z-] wire contract.
		{"replica-٥", "replica"},
	}
	for _, tc := range shortCases {
		got := Normalize(tc.in)
		if got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalize_Idempotent(t *testing.T) {
	for _, in := range []string{
		"REPLICA_1!",
		"abcdef-ghijklmnop",
		"fileviewer-v2-66b6c48dd5-abcde",
		"---a---b---c---",
	} {
		once := Normalize(in)
		twice := Normalize(once)
		if twice != once {
			t.Errorf("Normalize(Normalize(%q)) = %q, want %q", in, twice, once)
		}
	}
}

// TestNormalize_LongInputCollisionSafe covers the cr finding 1
// from PR #372 round 2: k8s pod hostnames (and docker-compose-
// scaled containers) share a long prefix and DIFFER only in their
// suffix. Plain prefix truncation would collapse them all to the
// same prefix and re-introduce the FRP NewProxy collision
// the salt exists to fix. The fix folds a sha256-derived suffix of
// the ORIGINAL raw input into the truncated output so distinct
// long inputs stay distinct.
func TestNormalize_LongInputCollisionSafe(t *testing.T) {
	// Two k8s pod names from the same ReplicaSet — the suffix is
	// the differentiating bit.
	a := "fileviewer-v2-66b6c48dd5-abcde"
	b := "fileviewer-v2-66b6c48dd5-fghij"

	gotA := Normalize(a)
	gotB := Normalize(b)

	if gotA == gotB {
		t.Errorf("Normalize collided on long-shared-prefix inputs: %q and %q both became %q — prefix truncation would re-introduce the FRP ErrProxyRepeated this PR exists to fix",
			a, b, gotA)
	}
	if len(gotA) > MaxDiscriminatorLen {
		t.Errorf("Normalize(%q) = %q (len %d), exceeds MaxDiscriminatorLen %d",
			a, gotA, len(gotA), MaxDiscriminatorLen)
	}
	if len(gotB) > MaxDiscriminatorLen {
		t.Errorf("Normalize(%q) = %q (len %d), exceeds MaxDiscriminatorLen %d",
			b, gotB, len(gotB), MaxDiscriminatorLen)
	}

	// Deterministic: the same input always produces the same salt.
	if Normalize(a) != gotA {
		t.Errorf("Normalize not deterministic on %q", a)
	}

	// docker compose --scale=N shape: project_svc_1, project_svc_2.
	c1 := "myproject_connector_1"
	c2 := "myproject_connector_2"
	gotC1 := Normalize(c1)
	gotC2 := Normalize(c2)
	if gotC1 == gotC2 {
		t.Errorf("Normalize collided on docker-compose-shaped names: %q and %q both became %q",
			c1, c2, gotC1)
	}

	seen := map[string]string{}
	for i := 0; i < 300; i++ {
		name := "fileviewer-v2-66b6c48dd5-replica-" + strconv.Itoa(i)
		got := Normalize(name)
		if prev, ok := seen[got]; ok {
			t.Fatalf("Normalize collided in 300-replica same-prefix sample: %q and %q both became %q", prev, name, got)
		}
		seen[got] = name
	}
}

// TestNormalize_ShortInputStablePrefix: inputs that fit within
// MaxDiscriminatorLen go through unchanged (no hash suffix). This
// keeps the resolver-branch ergonomics: a normal hostname like
// `pod-abc-7` stays human-readable in the proxy name.
func TestNormalize_ShortInputStablePrefix(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"pod-abc-7", "pod-abc-7"},
		{"host123", "host123"},
		{"a-b-c-d-e", "a-b-c-d-e"},
	}
	for _, tc := range cases {
		got := Normalize(tc.in)
		if got != tc.want {
			t.Errorf("Normalize(%q) = %q, want %q (short input must pass through)", tc.in, got, tc.want)
		}
	}
}

// TestNormalize_NoDoubleHyphenAfterTruncation pins the cr round 3
// finding: the prefix slice of a hyphen-collapsed value can
// legitimately END in a hyphen (e.g. `abcdef-ghijklmn` → prefix
// `abcdef-`). Without TrimRight'ing the prefix before joining with
// the "-" separator, the result emits `abcdef--<hash>` — a double
// hyphen that violates the hyphen-collapse contract Normalize
// documents.
func TestNormalize_NoDoubleHyphenAfterTruncation(t *testing.T) {
	// 7-char prefix of "abcdef-ghijklmnop" is "abcdef-" (ends in hyphen).
	// Result must NOT contain "--".
	got := Normalize("abcdef-ghijklmnop")
	if strings.Contains(got, "--") {
		t.Errorf("Normalize(%q) = %q contains double hyphen — TrimRight on the prefix slice failed", "abcdef-ghijklmnop", got)
	}
	// Also exercise a case where two hyphens fall at and just past
	// the cut point — the collapse handles consecutive hyphens
	// before truncation, but the prefix slice itself could still
	// land on a hyphen boundary.
	got2 := Normalize("abc-def-ghi-jkl-mno")
	if strings.Contains(got2, "--") {
		t.Errorf("Normalize(%q) = %q contains double hyphen", "abc-def-ghi-jkl-mno", got2)
	}
}

// MachineIDReader / HostnameReader nil defaults: the production
// resolver path uses os.Hostname / /etc/machine-id, which we can't
// safely assert here. This test just makes sure the nil-default
// branch doesn't panic — actual values are host-dependent.
func TestResolve_NilDefaultsDoNotPanic(t *testing.T) {
	r := &Resolver{
		Env: map[string]string{}, // suppress ECS/REPLICA_ID
	}
	got, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got == "" {
		t.Errorf("empty discriminator from nil-defaults path; the random fallback must always return SOMETHING")
	}
	// Source could be Hostname/MachineID/RandomFallback depending on
	// the test host. Just sanity-check it's a known value.
	switch meta.Source {
	case SourceHostname, SourceMachineID, SourceRandomFallback:
		// ok
	default:
		t.Errorf("Source = %q, want one of {hostname, machine-id, random-fallback}", meta.Source)
	}
}

// TestErrors_AccumulatesSoftFailures verifies the soft-error trail
// accumulates across earlier branches so operators can debug "why
// did the resolver land on machine-id instead of ECS?" from a single
// errors.Join output. The trail does not affect the resolved value.
func TestErrors_AccumulatesSoftFailures(t *testing.T) {
	r := &Resolver{
		Env: map[string]string{
			EnvECSContainerMetadataURI: "http://169.254.170.2/v4/abc",
		},
		ECS: func(ctx context.Context, endpoint string) (string, error) {
			return "", errors.New("connection refused")
		},
		Hostname: func() (string, error) { return "", errors.New("no hostname") },
		Machine:  func() (string, error) { return "fallback-mid", nil },
	}
	_, meta, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if meta.Source != SourceMachineID {
		t.Errorf("Source = %q, want %q (ECS errored, hostname errored, machine-id served)", meta.Source, SourceMachineID)
	}
	errsJoined := r.Errors()
	if errsJoined == nil {
		t.Fatal("Errors() = nil, want accumulated soft errors")
	}
	msg := errsJoined.Error()
	if !strings.Contains(msg, "ecs metadata fetch") {
		t.Errorf("Errors() missing ECS branch: %v", errsJoined)
	}
	if !strings.Contains(msg, "hostname read") {
		t.Errorf("Errors() missing hostname branch: %v", errsJoined)
	}
}

// TestResolve_DocumentsMachineIDFinding1Limitation: two Resolvers
// fed the SAME machine-id (the multi-replica-per-host case) AND no
// hostname fall through to machine-id and resolve to the same salt.
// This is the cr-finding-1 documented limitation: machine-id is
// shared on multi-replica-per-host orchestrators, so multi-replica
// deploys MUST use LAYERV_REPLICA_ID or rely on per-replica
// hostnames. The test pins the limitation: a future ranking change
// that breaks this invariant would break this test.
func TestResolve_DocumentsMachineIDFinding1Limitation(t *testing.T) {
	mkResolver := func() *Resolver {
		return &Resolver{
			Env:      map[string]string{}, // no LAYERV_REPLICA_ID, no ECS
			Hostname: func() (string, error) { return "", errors.New("no hostname") },
			Machine:  func() (string, error) { return "shared-host-mid", nil },
		}
	}
	a := mkResolver()
	b := mkResolver()
	gotA, _, _ := a.Resolve(context.Background())
	gotB, _, _ := b.Resolve(context.Background())
	if gotA != gotB {
		t.Errorf("two Resolvers fed the same machine-id resolved differently (%q vs %q) — the shared-host-mid invariant is broken", gotA, gotB)
	}
	// Long-input normalization adds a hash suffix; assert the
	// stable shape (opaque hash) rather than a literal
	// value. The point of the test is "same input → same output";
	// the exact hash bytes are a Normalize implementation detail.
	if len(gotA) > MaxDiscriminatorLen {
		t.Errorf("discriminator length = %d, exceeds MaxDiscriminatorLen %d", len(gotA), MaxDiscriminatorLen)
	}
	if len(gotA) != MaxDiscriminatorLen {
		t.Errorf("discriminator length = %d, want opaque %d-char hash", len(gotA), MaxDiscriminatorLen)
	}
}
