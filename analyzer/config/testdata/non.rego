package main

deny[msg] {
	rpl = input.spec[_].replicas
	rpl > 3
	msg = sprintf("too many replicas: %d", [rpl])
}

deny[msg] {
	rpl = input.spec.replicas
	rpl > 3
	msg = sprintf("too many replicas: %d", [rpl])
}
