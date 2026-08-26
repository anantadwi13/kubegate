// Package redact removes secret-bearing fields from Kubernetes API response
// bodies. It runs only in ro-nosecret, the one mode that makes a promise
// about content.
//
// It is pure: bytes and maps in, bytes and maps out. Every transformation is
// therefore testable as data, which matters because a mistake here silently
// voids a security guarantee rather than breaking loudly.
package redact

import (
	"encoding/json"
	"fmt"
	"strings"
)

// LastAppliedAnnotation is the load-bearing redaction. kubectl apply stores
// the entire submitted manifest here, so it routinely carries literal env
// values on objects the strict mode legitimately allows through.
const LastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

// Object redacts a single decoded API object in place and reports whether
// anything changed.
//
// kindHint supplies the kind for objects that carry none of their own --
// items inside a typed list, where a ConfigMapList's items are ConfigMaps
// but each item's "kind" field is empty. When neither the object nor the
// hint names a kind, the object is treated as unknown and its secret-shaped
// fields are stripped: fail closed.
func Object(obj map[string]any, kindHint string) bool {
	if obj == nil {
		return false
	}
	changed := false

	kind := kindHint
	if k, ok := obj["kind"].(string); ok && k != "" {
		kind = k
	}

	// data and stringData are stripped on every kind EXCEPT ConfigMap,
	// whose data is the whole reason to read one. Secret is already denied
	// by the ro-nosecret allowlist, so this is defense-in-depth against
	// secret-shaped fields on other kinds.
	if kind != "ConfigMap" {
		for _, f := range []string{"data", "stringData"} {
			if _, ok := obj[f]; ok {
				delete(obj, f)
				changed = true
			}
		}
	}

	if meta, ok := obj["metadata"].(map[string]any); ok {
		if anns, ok := meta["annotations"].(map[string]any); ok {
			if _, ok := anns[LastAppliedAnnotation]; ok {
				delete(anns, LastAppliedAnnotation)
				changed = true
			}
			if len(anns) == 0 {
				delete(meta, "annotations")
			}
		}
	}

	return changed
}

// Body redacts a complete JSON response body: a single object, a List, or a
// metav1.Table. It returns the transformed body and whether anything changed.
//
// A body that cannot be decoded is an error, never a passthrough. The caller
// must abort the response rather than forward bytes it could not inspect.
func Body(b []byte) ([]byte, bool, error) {
	var root map[string]any
	if err := json.Unmarshal(b, &root); err != nil {
		return nil, false, fmt.Errorf("decoding response body for redaction: %w", err)
	}

	changed := false
	kind, _ := root["kind"].(string)

	switch {
	case kind == "Table":
		changed = redactTable(root)
	case strings.HasSuffix(kind, "List"):
		changed = redactList(root, strings.TrimSuffix(kind, "List"))
	default:
		changed = Object(root, "")
	}

	if !changed {
		return b, false, nil
	}
	out, err := json.Marshal(root)
	if err != nil {
		return nil, false, fmt.Errorf("re-encoding redacted body: %w", err)
	}
	return out, true, nil
}

// redactList transforms every element of a List's items. itemKind is derived
// from the list kind, because list items carry no kind of their own.
func redactList(root map[string]any, itemKind string) bool {
	items, ok := root["items"].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, raw := range items {
		if obj, ok := raw.(map[string]any); ok {
			if Object(obj, itemKind) {
				changed = true
			}
		}
	}
	return changed
}

// redactTable transforms the embedded object of every Table row. kubectl
// renders from "cells", but rows also carry a PartialObjectMetadata whose
// annotations can hold the last-applied manifest.
func redactTable(root map[string]any) bool {
	rows, ok := root["rows"].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if obj, ok := row["object"].(map[string]any); ok {
			if Object(obj, "") {
				changed = true
			}
		}
	}
	return changed
}
