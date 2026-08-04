package apxchallenge

import "testing"

func human() Probes { return Probes{FillMs: 5000, Interactions: 8, Webdriver: false} }

func TestScoreOffAlwaysPasses(t *testing.T) {
	if ok, _ := ScoreProbes(Probes{Webdriver: true, FillMs: 1}, "off", 800); !ok {
		t.Fatal("off mode must always pass")
	}
}

func TestScoreLenientBlocksWebdriverAndTooFast(t *testing.T) {
	if ok, r := ScoreProbes(Probes{Webdriver: true, FillMs: 5000}, "lenient", 800); ok || r != "webdriver" {
		t.Fatalf("want block webdriver, got ok=%v r=%q", ok, r)
	}
	if ok, r := ScoreProbes(Probes{FillMs: 50}, "lenient", 800); ok || r != "too_fast" {
		t.Fatalf("want block too_fast, got ok=%v r=%q", ok, r)
	}
	if ok, _ := ScoreProbes(human(), "lenient", 800); !ok {
		t.Fatal("human should pass lenient")
	}
}

func TestScoreStrictAlsoNeedsInteraction(t *testing.T) {
	noInteract := Probes{FillMs: 5000, Interactions: 0}
	if ok, r := ScoreProbes(noInteract, "strict", 800); ok || r != "no_interaction" {
		t.Fatalf("strict must require interaction, got ok=%v r=%q", ok, r)
	}
	if ok, _ := ScoreProbes(noInteract, "lenient", 800); !ok {
		t.Fatal("lenient must NOT require interaction")
	}
}
