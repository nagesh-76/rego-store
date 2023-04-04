package policy.policy.rules
import future.keywords.if

default allow := false

# allow /finance/salary/{user} ingress
allow if {
    input.request.http.method == "GET"
    input.request.http.path == "/finance/salary/alice"
  }


 