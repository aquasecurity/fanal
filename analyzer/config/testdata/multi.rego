package testdata

denylist = [
	"hello"
]

deny[res] {
	val = input.metadata.name
	contains(val, denylist[_])

	res = {
		"type": "Metadata Name Settings",
		"msg": sprintf("deny: %s contains banned: %s", [val, denylist[i]]),
		"severity": "MEDIUM",
		"id": "RULE-10"
	}
}

warn[res] {
	rpl = input.spec.replicas
	rpl > 2
	res = {
		"type": "Replica Settings",
		"msg": sprintf("warn: too many replicas: %d", [rpl]),
		"severity": "LOW",
		"id": "RULE-100"
	}
}
