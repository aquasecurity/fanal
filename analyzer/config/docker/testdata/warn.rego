package testdata

warnlist = [
  "foo"
]

warn[msg] {
  input[i].Cmd == "from"
  val := input[i].Value
  contains(val[i], warnlist[_])

  msg = sprintf("warn: image found %s", [val])
}
