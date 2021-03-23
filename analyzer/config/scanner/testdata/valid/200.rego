package testdata.kubernetes.id_200

deny[res] {
  input.kind = "Deployment"
  res := {"type": "Kubernetes Check", "id": "ID-200", "msg": "deny", "severity": "HIGH"}
}
