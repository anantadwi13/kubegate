package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

func decode(t *testing.T, s string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("decoding fixture: %v", err)
	}
	return m
}

func TestObjectStripsSecretData(t *testing.T) {
	obj := decode(t, `{
		"apiVersion":"v1","kind":"Secret",
		"metadata":{"name":"db"},
		"data":{"password":"aHVudGVyMg=="},
		"stringData":{"user":"admin"}
	}`)
	if !Object(obj, "") {
		t.Error("Object must report a change")
	}
	if _, ok := obj["data"]; ok {
		t.Error("data must be removed from a Secret")
	}
	if _, ok := obj["stringData"]; ok {
		t.Error("stringData must be removed from a Secret")
	}
	if obj["metadata"] == nil {
		t.Error("metadata must survive")
	}
}

// The regression most likely to be introduced. A ConfigMap's data is the
// entire reason to read one.
func TestObjectPreservesConfigMapData(t *testing.T) {
	obj := decode(t, `{
		"apiVersion":"v1","kind":"ConfigMap",
		"metadata":{"name":"app-config"},
		"data":{"LOG_LEVEL":"debug"},
		"binaryData":{"blob":"AAEC"}
	}`)
	Object(obj, "")
	data, ok := obj["data"].(map[string]any)
	if !ok {
		t.Fatal("ConfigMap data must be preserved")
	}
	if data["LOG_LEVEL"] != "debug" {
		t.Errorf("ConfigMap data mangled: %v", data)
	}
	if _, ok := obj["binaryData"]; !ok {
		t.Error("ConfigMap binaryData must be preserved")
	}
}

func TestObjectPreservesConfigMapDataViaKindHint(t *testing.T) {
	// Items inside a ConfigMapList carry no kind of their own.
	obj := decode(t, `{"metadata":{"name":"app-config"},"data":{"K":"V"}}`)
	Object(obj, "ConfigMap")
	if obj["data"] == nil {
		t.Error("kindHint ConfigMap must preserve data")
	}
}

func TestObjectStripsDataWithoutKindOrHint(t *testing.T) {
	// Unknown kind: strip. Fail closed.
	obj := decode(t, `{"metadata":{"name":"x"},"data":{"K":"V"}}`)
	if !Object(obj, "") {
		t.Error("expected a change")
	}
	if _, ok := obj["data"]; ok {
		t.Error("data must be stripped when the kind is unknown")
	}
}

func TestObjectStripsLastAppliedAnnotation(t *testing.T) {
	obj := decode(t, `{
		"apiVersion":"apps/v1","kind":"Deployment",
		"metadata":{
			"name":"web",
			"annotations":{
				"kubectl.kubernetes.io/last-applied-configuration":"{\"spec\":{\"env\":[{\"name\":\"DB_PASSWORD\",\"value\":\"hunter2\"}]}}",
				"deployment.kubernetes.io/revision":"3"
			}
		}
	}`)
	if !Object(obj, "") {
		t.Error("Object must report a change")
	}
	meta := obj["metadata"].(map[string]any)
	anns := meta["annotations"].(map[string]any)
	if _, ok := anns[LastAppliedAnnotation]; ok {
		t.Error("last-applied annotation must be removed")
	}
	if anns["deployment.kubernetes.io/revision"] != "3" {
		t.Error("other annotations must survive")
	}
}

func TestObjectRemovesEmptyAnnotationsMap(t *testing.T) {
	obj := decode(t, `{
		"kind":"Deployment",
		"metadata":{"name":"web","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}"}}
	}`)
	Object(obj, "")
	meta := obj["metadata"].(map[string]any)
	if anns, ok := meta["annotations"]; ok {
		if m, isMap := anns.(map[string]any); !isMap || len(m) != 0 {
			t.Errorf("annotations = %v; an emptied map should be dropped or empty", anns)
		}
	}
}

// env[].value is deliberately NOT stripped. This is the sharpest edge of
// ro-nosecret and the spec records it as an accepted residual risk: a
// password typed directly into a manifest stays visible.
func TestObjectPreservesEnvValues(t *testing.T) {
	obj := decode(t, `{
		"kind":"Pod",
		"spec":{"containers":[{"name":"app","env":[{"name":"DB_PASSWORD","value":"hunter2"}]}]}
	}`)
	Object(obj, "")
	spec := obj["spec"].(map[string]any)
	c := spec["containers"].([]any)[0].(map[string]any)
	env := c["env"].([]any)[0].(map[string]any)
	if env["value"] != "hunter2" {
		t.Error("env values are intentionally preserved; see the spec's residual risks")
	}
}

func TestObjectNoChangeReturnsFalse(t *testing.T) {
	obj := decode(t, `{"kind":"Pod","metadata":{"name":"web"}}`)
	if Object(obj, "") {
		t.Error("Object must report no change for a clean object")
	}
}

func TestBodyList(t *testing.T) {
	body := []byte(`{
		"apiVersion":"v1","kind":"SecretList","metadata":{"resourceVersion":"7"},
		"items":[
			{"metadata":{"name":"a"},"data":{"k":"dg=="}},
			{"metadata":{"name":"b"},"data":{"k":"dg=="}}
		]
	}`)
	out, changed, err := Body(body)
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if !changed {
		t.Error("expected a change")
	}
	if strings.Contains(string(out), `"data"`) {
		t.Errorf("list items still contain data: %s", out)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(decoded["items"].([]any)) != 2 {
		t.Error("both items must survive")
	}
	if decoded["metadata"].(map[string]any)["resourceVersion"] != "7" {
		t.Error("list metadata must survive; clients need resourceVersion")
	}
}

func TestBodyConfigMapListPreservesData(t *testing.T) {
	body := []byte(`{
		"apiVersion":"v1","kind":"ConfigMapList",
		"items":[{"metadata":{"name":"a"},"data":{"LOG_LEVEL":"debug"}}]
	}`)
	out, _, err := Body(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "LOG_LEVEL") {
		t.Errorf("ConfigMapList items must keep their data: %s", out)
	}
}

func TestBodyTable(t *testing.T) {
	body := []byte(`{
		"kind":"Table","apiVersion":"meta.k8s.io/v1",
		"columnDefinitions":[{"name":"Name"}],
		"rows":[
			{"cells":["web"],"object":{"kind":"PartialObjectMetadata","metadata":{"name":"web","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{}"}}}}
		]
	}`)
	out, changed, err := Body(body)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("expected a change")
	}
	if strings.Contains(string(out), "last-applied-configuration") {
		t.Errorf("Table row objects must be redacted: %s", out)
	}
	if !strings.Contains(string(out), `"cells"`) {
		t.Error("Table cells must survive; kubectl renders from them")
	}
}

func TestBodyStatusPassesThrough(t *testing.T) {
	body := []byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","code":404}`)
	out, changed, err := Body(body)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("a Status body needs no redaction")
	}
	if !strings.Contains(string(out), "Failure") {
		t.Error("Status body must survive intact")
	}
}

func TestBodyMalformedJSONIsAnError(t *testing.T) {
	// Failing open here would silently void the mode's guarantee.
	for _, bad := range []string{`{"kind":`, `not json at all`, ``, `[1,2,3]`} {
		if _, _, err := Body([]byte(bad)); err == nil {
			t.Errorf("Body(%q) must return an error", bad)
		}
	}
}
