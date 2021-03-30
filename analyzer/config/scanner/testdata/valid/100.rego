package testdata.kubernetes.id_100

__rego_metadata__ := {
    "id": "XYZ-1234",
    "title": "My rule",
    "version": "v1.0.0",
    "severity": "HIGH",
    "type": "Kubernetes Security Check",
}

deny[res] {
  input.kind = "Deployment"
  res := {"type": "Kubernetes Check", "id": "ID-100", "msg": "deny", "severity": "CRITICAL"}
}
