package redact

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestStreamRedactsEachFrame(t *testing.T) {
	in := strings.Join([]string{
		`{"type":"ADDED","object":{"kind":"Secret","metadata":{"name":"a"},"data":{"k":"dg=="}}}`,
		`{"type":"MODIFIED","object":{"kind":"ConfigMap","metadata":{"name":"c"},"data":{"K":"V"}}}`,
		`{"type":"DELETED","object":{"kind":"Pod","metadata":{"name":"p","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}"}}}}`,
	}, "\n") + "\n"

	var out bytes.Buffer
	if err := Stream(&out, strings.NewReader(in), nil); err != nil {
		t.Fatalf("Stream: %v", err)
	}

	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d frames, want 3: %q", len(lines), out.String())
	}
	if strings.Contains(lines[0], `"data"`) {
		t.Errorf("Secret frame not redacted: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"K":"V"`) {
		t.Errorf("ConfigMap frame must keep its data: %s", lines[1])
	}
	if strings.Contains(lines[2], "last-applied") {
		t.Errorf("Pod frame annotation not redacted: %s", lines[2])
	}
	for i, l := range lines {
		var frame map[string]any
		if err := json.Unmarshal([]byte(l), &frame); err != nil {
			t.Errorf("frame %d is not valid JSON: %v", i, err)
		}
		if frame["type"] == nil {
			t.Errorf("frame %d lost its type field", i)
		}
	}
}

func TestStreamFlushesPerFrame(t *testing.T) {
	in := `{"type":"ADDED","object":{"kind":"Pod","metadata":{"name":"a"}}}` + "\n" +
		`{"type":"ADDED","object":{"kind":"Pod","metadata":{"name":"b"}}}` + "\n"
	flushes := 0
	var out bytes.Buffer
	if err := Stream(&out, strings.NewReader(in), func() { flushes++ }); err != nil {
		t.Fatal(err)
	}
	if flushes < 2 {
		t.Errorf("flush called %d times, want at least 2; watch output must not buffer", flushes)
	}
}

func TestStreamSkipsBlankLines(t *testing.T) {
	in := "\n" + `{"type":"ADDED","object":{"kind":"Pod","metadata":{"name":"a"}}}` + "\n\n"
	var out bytes.Buffer
	if err := Stream(&out, strings.NewReader(in), nil); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(strings.TrimRight(out.String(), "\n"), "\n"); n != 0 {
		t.Errorf("expected exactly one frame out, got %q", out.String())
	}
}

func TestStreamMalformedFrameIsAnError(t *testing.T) {
	in := `{"type":"ADDED","object":{"kind":"Pod"}}` + "\n" + `{ broken` + "\n"
	var out bytes.Buffer
	err := Stream(&out, strings.NewReader(in), nil)
	if err == nil {
		t.Fatal("a malformed frame must return an error, not be forwarded")
	}
	if strings.Contains(out.String(), "broken") {
		t.Error("the malformed frame must not reach the client")
	}
}

func TestStreamHandlesLargeFrame(t *testing.T) {
	// bufio.Scanner's default 64KiB token limit would reject a large object;
	// real pod specs with big annotations exceed it.
	big := strings.Repeat("x", 200_000)
	in := `{"type":"ADDED","object":{"kind":"Pod","metadata":{"name":"` + big + `"}}}` + "\n"
	var out bytes.Buffer
	if err := Stream(&out, strings.NewReader(in), nil); err != nil {
		t.Fatalf("Stream must handle frames larger than 64KiB: %v", err)
	}
	if !strings.Contains(out.String(), big) {
		t.Error("large frame was truncated")
	}
}

func TestStreamEmptyInput(t *testing.T) {
	var out bytes.Buffer
	if err := Stream(&out, strings.NewReader(""), nil); err != nil && err != io.EOF {
		t.Errorf("empty input must not error: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("empty input produced output: %q", out.String())
	}
}
