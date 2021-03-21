package testdata

denylist = [
]

deny[msg] {
	input[i].Cmd == "from"
	val := input[i].Value
	contains(val[i], denylist[_])

	msg = sprintf("deny: image found %s", [val])
}
