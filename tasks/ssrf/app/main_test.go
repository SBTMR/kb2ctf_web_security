package main

import (
    "net/http/httptest"
    "strings"
    "testing"
)

func TestInternalRejectsAnonymous(t *testing.T) {
    result := httptest.NewRecorder()
    handler("internal").ServeHTTP(result, httptest.NewRequest("GET", "/flag", nil))
    if result.Code != 401 { t.Fatalf("expected unauthorized, got %d", result.Code) }
}

func TestSampleNormalFlow(t *testing.T) {
    result := httptest.NewRecorder()
    handler("sample").ServeHTTP(result, httptest.NewRequest("GET", "/", nil))
    if result.Code != 200 || !strings.Contains(result.Body.String(), "sample-site") { t.Fatal("missing sample content") }
}

func TestSampleHealth(t *testing.T) {
    result := httptest.NewRecorder()
    handler("sample").ServeHTTP(result, httptest.NewRequest("GET", "/healthz", nil))
    if result.Code != 200 { t.Fatal("sample not healthy") }
}
