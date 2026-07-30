package secdesc

import "testing"

func TestSIDRoundTrip(t *testing.T) {
	cases := []string{
		"S-1-5-21-1004336348-1177238915-682003330-512",
		"S-1-5-32-544",
		"S-1-1-0",
		"S-1-5-11",
	}
	for _, want := range cases {
		b, err := SIDToBytes(want)
		if err != nil {
			t.Fatalf("SIDToBytes(%s): %v", want, err)
		}
		got, err := ParseSID(b)
		if err != nil {
			t.Fatalf("ParseSID after encode(%s): %v", want, err)
		}
		if got != want {
			t.Fatalf("round trip mismatch: got %s want %s", got, want)
		}
	}
}

func TestSIDToBytesRejectsGarbage(t *testing.T) {
	if _, err := SIDToBytes("not-a-sid"); err == nil {
		t.Fatal("expected error for non-SID input")
	}
}
