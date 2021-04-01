package main.hcl.xyz_100

__rego_metadata__ := {
    "id": "XYZ-100",
    "title": "Bad HCL",
    "version": "v1.0.0",
    "severity": "HIGH",
    "type": "HCL Security Check",
}

deny[msg] {
	rpl = input.spec.replicas
	rpl > 3
	msg = sprintf("too many replicas: %d", [rpl])
}
