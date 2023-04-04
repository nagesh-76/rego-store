package policy.policy.rules

import future.keywords.if

default check := false

check if {
	is_post
	is_sandbox
	contains(claims.iss,"archinsurance-dev")
}

is_post if input.request.http.method == "GET"

is_sandbox if input.request.http.path == "/sandbox/hello"

claims := payload if {
	[_, payload, _] := io.jwt.decode(bearer_token)
}

bearer_token := t if {
	v := input.request.http.headers.authorization
	startswith(v, "Bearer ")
	t := substring(v, count("Bearer "), -1)
}