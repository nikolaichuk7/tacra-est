package mockca_test

// Interop and security findings for the TACRA EST profile, run against the TWI SIG reference
// implementation (github.com/globalsign/est, TWI-Unified-Model fork) through its public API.
// Contributed toward draft-novak-lamps-tacra-est. These are not assertions of a production
// vulnerability; they are implementation-status findings on a POC, phrased as reproducing tests.

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"

	"github.com/globalsign/est"
	"github.com/globalsign/est/internal/mockca"
)

func newAttested(t *testing.T) (*mockca.AttestedCA, *ecdsa.PrivateKey) {
	t.Helper()
	base, err := mockca.NewTransient()
	if err != nil {
		t.Fatalf("NewTransient: %v", err)
	}
	provider, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("provider key: %v", err)
	}
	return mockca.NewAttested(base, nil, provider.Public()), provider
}

func csrDER(t *testing.T, cn string) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// T1: the happy path works, so the harness is faithful to the implementation.
func TestInterop_HappyEnroll(t *testing.T) {
	ca, provider := newAttested(t)
	ctx := context.Background()
	r := httptest.NewRequest("GET", "/", nil)

	init, err := ca.InitiateRemoteAttestation(ctx, mockca.DefaultEnrollTarget, "", "", r)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	ev, err := est.NewMockEvidence(provider, init.FreshnessKind, init.Handle)
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	der := csrDER(t, "workload")
	cert, err := ca.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
		Target: mockca.DefaultEnrollTarget, FreshnessKind: init.FreshnessKind, Handle: init.Handle,
		CSR: der, Evidence: ev, Binding: est.Binding{Method: est.BindingCSRHash},
	}, "", r)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if cert == nil {
		t.Fatal("no certificate")
	}
}

// T2 (finding): the csr-hash binding is declared and its presence is checked, but the value is
// never bound to Evidence (the mock EAT omits the CSR, and CSRHash() is never called on the
// verify path). A conduit that swaps the CSR after Evidence is produced still obtains a
// certificate for the swapped key. This is the server/CSR-substitution gap the pull request
// closes with the server_id + CSR digest in the binding input.
func TestInterop_CSRNotBoundToEvidence(t *testing.T) {
	ca, provider := newAttested(t)
	ctx := context.Background()
	r := httptest.NewRequest("GET", "/", nil)

	init, err := ca.InitiateRemoteAttestation(ctx, mockca.DefaultEnrollTarget, "", "", r)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	// The Attester intends csrA and produces Evidence bound to the Handle.
	csrA := csrDER(t, "intended-workload")
	ev, err := est.NewMockEvidence(provider, init.FreshnessKind, init.Handle)
	if err != nil {
		t.Fatalf("evidence: %v", err)
	}
	// The conduit substitutes csrB, a different key, and forwards the genuine Evidence.
	csrB := csrDER(t, "attacker-workload")
	if string(est.CSRHash(csrA)) == string(est.CSRHash(csrB)) {
		t.Fatal("test setup: the two CSRs must differ")
	}
	cert, err := ca.EnrollCredential(ctx, &est.AttestedEnrollmentRequest{
		Target: mockca.DefaultEnrollTarget, FreshnessKind: init.FreshnessKind, Handle: init.Handle,
		CSR: csrB, Evidence: ev, Binding: est.Binding{Method: est.BindingCSRHash},
	}, "", r)
	if err != nil {
		t.Fatalf("FINDING NOT REPRODUCED: swapped CSR was refused: %v", err)
	}
	// The certificate is for csrB's key, not csrA's: the substitution was accepted.
	want, _ := x509.ParseCertificateRequest(csrB)
	if !cert.PublicKey.(interface{ Equal(x crypto.PublicKey) bool }).Equal(want.PublicKey) {
		t.Fatal("certificate is not for the substituted key")
	}
	t.Logf("FINDING: a certificate was issued for a CSR the Attester never bound to Evidence")
}

// T3 (finding): the EncryptedCredentialBundle authenticates the CEKpub-holder relationship but
// not the sender. CEKpub travels in the retrieval request through the untrusted conduit, so any
// party that sees it can seal a bundle the Attester will open. This is the bundle-substitution
// gap the pull request closes with HPKE mode_auth or a Vault signature.
func TestInterop_BundleOriginNotAuthenticated(t *testing.T) {
	// The Attester's CEK; only CEKpub leaves the Attester, in the request.
	cek, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cekPub := cek.PublicKey().Bytes()

	// An attacker holding only CEKpub seals a bundle of its own choosing.
	attacker := &est.CredentialBundle{
		GroupID:         "any-group",
		CredentialItems: []est.CredentialItem{{Type: est.CredentialItemPKCS8Key, Data: []byte("attacker-chosen key material")}},
	}
	sealed, err := est.SealCredentialBundle(attacker, cekPub, []byte("handle"), "", "impersonated-vault")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// The Attester opens it and would use the attacker's credential.
	opened, err := sealed.Open(cek)
	if err != nil {
		t.Fatalf("FINDING NOT REPRODUCED: bundle rejected: %v", err)
	}
	if string(opened.CredentialItems[0].Data) != "attacker-chosen key material" {
		t.Fatal("unexpected bundle contents")
	}
	t.Logf("FINDING: a bundle sealed with only CEKpub, by no Vault, was accepted by the Attester")
}
