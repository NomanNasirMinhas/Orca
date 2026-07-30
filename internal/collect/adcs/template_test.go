package adcs

import (
	"testing"

	"orca/internal/model"
)

func has(fs []model.Fact, p model.Pred, a, b string) bool {
	for _, f := range fs {
		if f.Pred == p && f.A == a && f.B == b {
			return true
		}
	}
	return false
}

// A classic ESC1-vulnerable template: enrollee supplies subject, client-auth
// EKU, no manager approval, published on an online CA, low-priv can enroll.
func TestESC1Atoms(t *testing.T) {
	tmpl := Template{
		SID:          "S-T1",
		Name:         "VulnUser",
		NameFlags:    ctFlagEnrolleeSuppliesSubject,
		EnrollFlags:  0, // no PEND_ALL_REQUESTS => no approval
		EKUs:         []string{"1.3.6.1.5.5.7.3.2"},
		Published:    true,
		CAOnline:     true,
		EnrolleeSIDs: []string{"S-LOW"},
	}
	fs := tmpl.Facts()
	for _, want := range []model.Pred{
		model.IsTemplate, model.TemplateEnrolleeSuppliesSubject,
		model.TemplateAuthEKU, model.TemplateNoManagerApproval, model.CAReachable,
	} {
		if !has(fs, want, "S-T1", "") {
			t.Fatalf("missing atom %s: %+v", want, fs)
		}
	}
	if !has(fs, model.CanEnroll, "S-LOW", "S-T1") {
		t.Fatalf("missing CanEnroll: %+v", fs)
	}
}

func TestManagerApprovalSuppressesAtom(t *testing.T) {
	tmpl := Template{SID: "S-T1", EnrollFlags: ctFlagPendAllRequests}
	if has(tmpl.Facts(), model.TemplateNoManagerApproval, "S-T1", "") {
		t.Fatal("manager approval required must suppress NoManagerApproval atom")
	}
}

func TestEmptyEKUCountsAsAuth(t *testing.T) {
	tmpl := Template{SID: "S-T1", EKUs: nil}
	if !has(tmpl.Facts(), model.TemplateAuthEKU, "S-T1", "") {
		t.Fatal("empty EKU list should be treated as auth-capable")
	}
}

func TestNonAuthEKUExcluded(t *testing.T) {
	// Encrypting File System EKU only: not usable for authentication.
	tmpl := Template{SID: "S-T1", EKUs: []string{"1.3.6.1.4.1.311.10.3.4"}}
	if has(tmpl.Facts(), model.TemplateAuthEKU, "S-T1", "") {
		t.Fatal("non-auth EKU must not yield TemplateAuthEKU")
	}
}

func TestOfflineCANotReachable(t *testing.T) {
	tmpl := Template{SID: "S-T1", Published: true, CAOnline: false}
	if has(tmpl.Facts(), model.CAReachable, "S-T1", "") {
		t.Fatal("offline CA must not yield CAReachable")
	}
}
