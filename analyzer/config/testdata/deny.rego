package main

denylist = [
	"hello"
]

deny[res] {
	val = input.metadata[_].name
	contains(val, denylist[_])

	res = {
		"type": "Metadata Name Settings",
		"msg": sprintf("deny: %s contains banned: %s", [val, denylist[i]]),
		"severity": "MEDIUM",
		"id": "RULE-10"
	}
}

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

