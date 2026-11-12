# strip-options.awk: the copy of ateapi.proto that `make proto` generates the
# Go stubs from (GAP-0014). Upstream declares its resource and method
# annotations as extensions 50000 of google.protobuf.MessageOptions and
# MethodOptions, the numbers the OpenShell SDK's optionsv1 also registers, so
# a binary that links both panics in protoregistry at init. This drops the two
# extend blocks, every (resource) and (method) option that uses them and the
# then-unused descriptor.proto import. Options are descriptor metadata only:
# messages, fields, services and the wire format are unchanged. The
# ResourceAnnotation, MethodAnnotation and Scope messages stay as plain
# messages. The vendored ateapi.proto itself stays byte-identical to upstream.
/^import "google\/protobuf\/descriptor\.proto";$/ { next }
/^extend google\.protobuf\.(Message|Method)Options \{$/ { inext = 1; next }
inext { if ($0 ~ /^\}$/) inext = 0; next }
/^[ \t]*option \(resource\) = \{[ \t]*$/ { inopt = 1; next }
inopt { if ($0 ~ /^[ \t]*\};[ \t]*$/) inopt = 0; next }
/^[ \t]*option \(method\)\.resource = "[A-Za-z]+";[ \t]*$/ { next }
/option \((resource|method)\)/ { print "strip-options.awk: unhandled option form at line " NR ": " $0 > "/dev/stderr"; failed = 1 }
/^extend / { print "strip-options.awk: unhandled extend at line " NR ": " $0 > "/dev/stderr"; failed = 1 }
{ print }
END { if (inext || inopt) { print "strip-options.awk: unterminated block" > "/dev/stderr"; failed = 1 } if (failed) exit 1 }
