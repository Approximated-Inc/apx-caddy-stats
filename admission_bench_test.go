package apxstats

import (
	"net/http"
	"testing"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func BenchmarkAdmissionAdmit(b *testing.B) {
	overload.cfg.Store(resolveOverloadConfig(&OverloadConfig{Admission: &AdmissionConfig{Mode: "enforce"}}, 1<<30))
	defer overload.cfg.Store(nil)
	r := admissionReq("GET", "/static/app.js?v=1")
	w := &nopWriter{h: http.Header{}}
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = AdmissionHandler{}.ServeHTTP(w, r, next)
	}
}

func BenchmarkAdmissionShed(b *testing.B) {
	overload.cfg.Store(resolveOverloadConfig(&OverloadConfig{Admission: &AdmissionConfig{Mode: "enforce"}}, 1<<30))
	overload.level.Store(2)
	admissionLimitNow.Store(8)
	admissionInflight.Store(100)
	defer func() {
		overload.cfg.Store(nil)
		overload.level.Store(0)
		admissionLimitNow.Store(0)
		admissionInflight.Store(0)
	}()
	r := admissionReq("GET", "/static/app.js?v=1")
	w := &nopWriter{h: http.Header{}}
	next := caddyhttp.HandlerFunc(func(http.ResponseWriter, *http.Request) error { return nil })
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = AdmissionHandler{}.ServeHTTP(w, r, next)
	}
}
