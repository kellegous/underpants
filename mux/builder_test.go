package mux

import (
	"bytes"
	"net/http"
	"testing"
)

type respWriter struct {
	bytes.Buffer
	status  int
	headers http.Header
}

func newResponseWriter() *respWriter {
	return &respWriter{
		headers: http.Header(map[string][]string{}),
		status:  http.StatusOK,
	}
}

func (r *respWriter) WriteHeader(status int) {
	r.status = status
}

func (r *respWriter) Header() http.Header {
	return r.headers
}

func (r *respWriter) Reset() {
	r.Buffer.Reset()
	r.headers = http.Header(map[string][]string{})
	r.status = http.StatusOK
}

type resetter interface {
	Reset()
}

func resetAll(items ...resetter) {
	for _, item := range items {
		item.Reset()
	}
}

func TestBuilder(t *testing.T) {
	b := Create()

	var ah handler
	b.ForHost("a.com").Handle("/", &ah)

	var dh handler
	b.ForAnyHost().Handle("/", &dh)

	s := b.Build()

	rw := newResponseWriter()
	s.ServeHTTP(rw, requestTo("a.com", "/"))
	if rw.status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rw.status)
	}
	if !ah.WasCalled() {
		t.Fatal("ah should have been called but wasn't")
	}
	if dh.WasCalled() {
		t.Fatal("dh was called but shouldn't have been")
	}

	resetAll(&ah, &dh, rw)
	s.ServeHTTP(rw, requestTo("a.com:8080", "/"))
	if rw.status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rw.status)
	}
	if !ah.WasCalled() {
		t.Fatal("ah should have been called but wasn't")
	}
	if dh.WasCalled() {
		t.Fatal("dh was called but shouldn't have been")
	}

	resetAll(&ah, &dh, rw)
	s.ServeHTTP(rw, requestTo("c.com", "/"))
	if rw.status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rw.status)
	}
	if !dh.WasCalled() {
		t.Fatal("dh should have been called but wasn't")
	}
	if ah.WasCalled() {
		t.Fatal("ah was called but shouldn't have been")
	}

	resetAll(&ah, &dh, rw)
	s.ServeHTTP(rw, requestTo("", "/"))
	if rw.status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rw.status)
	}
	if !dh.WasCalled() {
		t.Fatal("dh should have been called but wasn't")
	}
	if ah.WasCalled() {
		t.Fatal("ah was called but shouldn't have been")
	}
}

func TestNotFound(t *testing.T) {
	b := Create()

	var ah handler
	b.ForHost("a.com").Handle("/", &ah)

	var bh handler
	b.ForAnyHost().Handle("/foo", &bh)

	s := b.Build()

	rw := newResponseWriter()
	s.ServeHTTP(rw, requestTo("b.com", "/"))
	if rw.status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rw.status)
	}
	if bh.WasCalled() {
		t.Fatal("bh was called but shouldn't have been")
	}
	if ah.WasCalled() {
		t.Fatal("ah was called but shouldn't have been")
	}

	s.ServeHTTP(rw, requestTo("", "/"))
	if rw.status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rw.status)
	}
	if bh.WasCalled() {
		t.Fatal("bh was called but shouldn't have been")
	}
	if ah.WasCalled() {
		t.Fatal("ah was called but shouldn't have been")
	}
}

func TestEmpty(t *testing.T) {
	s := Create().Build()

	rw := newResponseWriter()
	s.ServeHTTP(rw, requestTo("", "/"))
	if rw.status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rw.status)
	}
}

func TestPortStripping(t *testing.T) {
	b := Create()

	var ah handler
	b.ForHost("a.com").Handle("/", &ah)

	var bh handler
	b.ForHost("a.com:8080").Handle("/foo", &bh)

	s := b.Build()

	rw := newResponseWriter()
	s.ServeHTTP(rw, requestTo("a.com", "/foo"))
	if rw.status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rw.status)
	}
	if !bh.WasCalled() {
		t.Fatal("bh should have been called but wasn't")
	}
	if ah.WasCalled() {
		t.Fatal("ah was called but shouldn't have been")
	}

	resetAll(&ah, &bh, rw)
	s.ServeHTTP(rw, requestTo("a.com:9090", "/foo"))
	if rw.status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rw.status)
	}
	if !bh.WasCalled() {
		t.Fatal("bh should have been called but wasn't")
	}
	if ah.WasCalled() {
		t.Fatal("ah was called but shouldn't have been")
	}
}
