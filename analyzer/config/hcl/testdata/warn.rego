package testdata

warn[msg] {
    rpl = input.spec[_].replicas
	rpl > 2
    msg = sprintf("warn: too many replicas: %d", [rpl])
}
