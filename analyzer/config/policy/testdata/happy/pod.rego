package testdata.kubernetes.xyz_200

__rego_metadata__ := {
    "id": "XYZ-200",
    "title": "Bad Pod",
    "version": "v1.0.0",
    "severity": "CRITICAL",
    "type": "Kubernetes Security Check",
}

deny[msg] {
  input.kind == "Pod"
  msg := sprintf("deny %s", [input.metadata.name])
}
