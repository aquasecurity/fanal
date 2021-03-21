package main

warn[res] {
	rpl = input.spec[_].replicas
	rpl > 2
	res = {"type": "Replica Settings", "msg": sprintf("warn: too many replicas: %d", [rpl]), "severity": "LOW", "id": "RULE-100"}
}

warn[res] {
	rpl = input.spec.replicas
	rpl > 2
	res = {"type": "Replica Settings", "msg": sprintf("warn: too many replicas: %d", [rpl]), "severity": "LOW", "id": "RULE-100"}
}
