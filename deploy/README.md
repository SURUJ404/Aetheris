# Deployment scaffold

Add pinned, reviewed Compose/Kubernetes manifests here after service boundaries are stable.
Production deployment must include secret management, network policies, non-root containers,
resource requests/limits, health checks, backup/restore procedures and image scanning.
Do not publish database/cache/admin ports publicly by default.
