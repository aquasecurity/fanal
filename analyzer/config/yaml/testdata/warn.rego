package testdata

warn[msg] {
    rpl = input.spec.replicas
	rpl > 2
    msg = sprintf("warn: too many replicas: %d", [rpl])
}
