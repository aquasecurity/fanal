package testdata

deny[msg] {
    rpl = input.spec[_].replicas
	rpl > 3
    msg = sprintf("too many replicas: %d", [rpl])
}
