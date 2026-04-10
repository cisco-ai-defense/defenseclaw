package scanner

import (
	"testing"
)

func TestExtractJSON(t *testing.T) {
	t.Run("simple_object", func(t *testing.T) {
		input := []byte(`some text {"key":"value"} trailing`)
		got := string(extractJSON(input))
		want := `{"key":"value"}`
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("nested_braces", func(t *testing.T) {
		input := []byte(`prefix {"a":{"b":"c"}} suffix`)
		got := string(extractJSON(input))
		want := `{"a":{"b":"c"}}`
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("braces_inside_strings", func(t *testing.T) {
		input := []byte(`text {"msg":"hello { world }"} end`)
		got := string(extractJSON(input))
		want := `{"msg":"hello { world }"}`
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("escaped_quote_in_string", func(t *testing.T) {
		input := []byte(`pre {"k":"val\"ue"} post`)
		got := string(extractJSON(input))
		want := `{"k":"val\"ue"}`
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("no_json_object", func(t *testing.T) {
		input := []byte(`no json here`)
		got := string(extractJSON(input))
		if got != string(input) {
			t.Errorf("expected original input returned, got %q", got)
		}
	})

	t.Run("multiple_objects_returns_first", func(t *testing.T) {
		input := []byte(`{"first":1} {"second":2}`)
		got := string(extractJSON(input))
		want := `{"first":1}`
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("unbalanced_braces_returns_input", func(t *testing.T) {
		input := []byte(`{"incomplete`)
		got := string(extractJSON(input))
		if got != string(input) {
			t.Errorf("expected original input for unbalanced braces, got %q", got)
		}
	})

	t.Run("object_with_array_inside", func(t *testing.T) {
		input := []byte(`noise {"items":[1,2,{"nested":true}]} more`)
		got := string(extractJSON(input))
		want := `{"items":[1,2,{"nested":true}]}`
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	t.Run("ansi_prefix_then_json", func(t *testing.T) {
		input := []byte("\033[32m{\"status\":\"ok\"}\033[0m")
		cleaned := ansiRe.ReplaceAll(input, nil)
		got := string(extractJSON(cleaned))
		want := `{"status":"ok"}`
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})
}
