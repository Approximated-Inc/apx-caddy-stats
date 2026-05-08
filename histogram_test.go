package apxstats

import (
	"testing"
	"time"
)

func TestBucketForUs(t *testing.T) {
	cases := []struct {
		us   uint64
		want int
	}{
		{0, 0},
		{1, 0},
		{999, 0},
		{1_000, 1},
		{1_999, 1},
		{2_000, 2},
		{4_999, 2},
		{5_000, 3},
		{99_999, 6},
		{100_000, 7},
		{249_999, 7},
		{250_000, 8},
		{999_999, 9},
		{1_000_000, 10},
		{59_999_999, 14},
		{60_000_000, 15},
		{1_000_000_000, 15}, // 1000s — well above all finite bounds
	}
	for _, c := range cases {
		got := BucketForUs(c.us)
		if got != c.want {
			t.Errorf("BucketForUs(%d) = %d; want %d", c.us, got, c.want)
		}
	}
}

func TestHistKeyTable(t *testing.T) {
	want := []string{
		"lat_b00", "lat_b01", "lat_b02", "lat_b03",
		"lat_b04", "lat_b05", "lat_b06", "lat_b07",
		"lat_b08", "lat_b09", "lat_b10", "lat_b11",
		"lat_b12", "lat_b13", "lat_b14", "lat_b15",
	}
	for i, w := range want {
		if got := histKey(i); got != w {
			t.Errorf("histKey(%d) = %q; want %q", i, got, w)
		}
	}
}

func TestFormatTs_MinuteAligned(t *testing.T) {
	want := "2026-05-08T09:30:00Z"
	ts, err := time.Parse(time.RFC3339, want)
	if err != nil {
		t.Fatal(err)
	}
	unixMin := uint32(ts.Unix() / 60)
	if got := formatTs(unixMin); got != want {
		t.Fatalf("formatTs round-trip: got %q want %q", got, want)
	}
}
