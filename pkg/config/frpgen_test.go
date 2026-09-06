package config

import "testing"

func TestFRPProxyNameNormalizesAndKeepsLongNamesDistinct(t *testing.T) {
	if got := FRPProxyName("web", " Replica__ONE!! "); got != "web-replicaone" {
		t.Fatalf("FRPProxyName() = %q, want web-replicaone", got)
	}
	a := FRPProxyName("web", "fileviewer-v2-66b6c48dd5-abcde")
	b := FRPProxyName("web", "fileviewer-v2-66b6c48dd5-fghij")
	if a == b || len(a) > len("web-")+maxProxyDiscriminatorLen || len(b) > len("web-")+maxProxyDiscriminatorLen {
		t.Fatalf("long proxy names = %q, %q", a, b)
	}
}
