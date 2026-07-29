package apxchallenge

import (
	"testing"
	"time"
)

const ftSecret = "test-secret-form"

func TestFormChallengeRoundTrip(t *testing.T) {
	tok := IssueFormChallenge(ftSecret, "203.0.113.7", 12, time.Now().Add(time.Minute))
	p, err := VerifyFormChallenge(ftSecret, tok, "203.0.113.9") // same /24
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.Diff != 12 {
		t.Fatalf("difficulty not carried: got %d", p.Diff)
	}
}

func TestFormChallengeRejectsOtherPrefix(t *testing.T) {
	tok := IssueFormChallenge(ftSecret, "203.0.113.7", 12, time.Now().Add(time.Minute))
	if _, err := VerifyFormChallenge(ftSecret, tok, "198.51.100.7"); err == nil {
		t.Fatal("expected prefix mismatch rejection")
	}
}

func TestFormChallengeRejectsExpired(t *testing.T) {
	tok := IssueFormChallenge(ftSecret, "203.0.113.7", 12, time.Now().Add(-time.Second))
	if _, err := VerifyFormChallenge(ftSecret, tok, "203.0.113.7"); err == nil {
		t.Fatal("expected expiry rejection")
	}
}

func TestFormTokenRoundTripAndHostBinding(t *testing.T) {
	tok := IssueFormToken(ftSecret, "203.0.113.7", "shop.example.com", "n1", time.Now().Add(time.Minute))
	if _, err := VerifyFormToken(ftSecret, tok, "203.0.113.7", "shop.example.com"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if _, err := VerifyFormToken(ftSecret, tok, "203.0.113.7", "evil.example.com"); err == nil {
		t.Fatal("expected host mismatch rejection")
	}
}

func TestFormTokenDomainSeparation(t *testing.T) {
	// A challenge token must NOT validate as a form token and vice versa.
	ch := IssueFormChallenge(ftSecret, "203.0.113.7", 12, time.Now().Add(time.Minute))
	if _, err := VerifyFormToken(ftSecret, ch, "203.0.113.7", "shop.example.com"); err == nil {
		t.Fatal("challenge token validated as form token")
	}
}
