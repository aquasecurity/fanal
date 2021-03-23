package testdata.kubernetes.id_100

deny[res] {
  input.kind = "Deployment"
  res := {"type": "Kubernetes Check", "id": "ID-100", "msg": "deny", "severity": "CRITICAL"}
}
