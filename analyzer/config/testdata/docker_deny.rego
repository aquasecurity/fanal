package testdata 

denylist = [
	"foo"
]

deny[res] {
	input[i].Cmd == "from"
	val := input[i].Value
	contains(val[i], denylist[_])

	res = {"type": "Docker Security Check", "msg": sprintf("deny: image found %s", [val]), "severity": "HIGH", "id": "RULE-100"}
}
