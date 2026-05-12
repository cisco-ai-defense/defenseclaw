package dctest.malformed

# Deliberately malformed Rego. The closing brace is missing and the rule
# body has invalid syntax. Used by error.rego cases.

default allow = false

allow {
  input.user == "admin"
  input.action ==
}
