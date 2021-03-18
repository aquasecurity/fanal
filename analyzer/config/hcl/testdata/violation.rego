package testdata

violation[{"msg": msg, "details":{}}] {
    rpl = input.spec[_].replicas
	rpl > 2
    msg = sprintf("violation: too many replicas: %d", [rpl])
}
