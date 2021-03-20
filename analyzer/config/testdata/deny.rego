package testdata

deny[msg] {
	rpl = input.spec[_].replicas
	rpl > 2
	msg = sprintf("deny: too many replicas: %d", [rpl])
}

deny[msg] {
	rpl = input.spec.replicas
	rpl > 2
	msg = sprintf("deny: too many replicas: %d", [rpl])
}
