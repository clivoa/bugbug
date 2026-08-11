---
name: cloud-exposure
version: "1.0.0"
description: "S3 bucket discovery, cloud metadata endpoints, IAM privilege analysis"
risk_level: "L0-L2"
approval: "L0 auto, L1 auto, L2 requires explicit approval"
program_types: [cloud, web2, api]
source: "reviewed from reference repositories"
actions: []
---

# Cloud & DevOps Exposure Testing

**status:** active
**risk:** L0–L2
**approval:** L0 auto, L1 auto, L2 requires explicit approval
**program_types:** [cloud, web2, api]
**source:** reviewed from reference repositories

## Cloud Service Discovery

### Object Storage (S3, GCS, Azure Blob)
- **Bucket enumeration** — brute-force org-related bucket names
- **Open buckets** — test read access to discovered buckets
- **Authenticated enumeration** — can authenticated user list bucket contents?
- **Cross-tenant access** — Azure storage account name confusion
- **Signed URL manipulation** — parameter modification, expiry extension
- **Bucket policy misconfig** — overly permissive principal: "*"

### Cloud Metadata Endpoints
- AWS: 169.254.169.254/latest/meta-data/
- GCP: metadata.google.internal/computeMetadata/v1/
- Azure: 169.254.169.254/metadata/instance
- DigitalOcean: 169.254.169.254/metadata/v1/
- Oracle: 169.254.169.254/opc/v2/instance/
- **SSRF → metadata** — IAM credentials, SSH keys, user-data
- **IMDSv1 vs v2** — if IMDSv2 enforced, token-requirement blocks simple SSRF

### Container & Orchestration
- Exposed Docker API (2375, 2376)
- Kubernetes API server exposure
- etcd without authentication (2379)
- Kubernetes dashboard (kubectl proxy, dashboard service)
- Helm/Tiller exposure (44134)
- Container registry access — anonymous pull?

### CI/CD Pipeline
- Exposed Jenkins, GitLab CI, GitHub Actions runners
- Pipeline configuration with hardcoded secrets
- Build artifacts containing credentials
- Webhook endpoints without authentication

## Detection Approach

1. Subdomain discovery → identify cloud-hosted subdomains (CNAME analysis)
2. Spider/crawl → identify cloud resource URLs in JS, HTML, API responses
3. DNS analysis → CNAME records pointing to cloud services
4. Error message analysis → verbose errors revealing bucket names, account IDs
5. CSP header analysis → cloud resources in connect-src, img-src directives

## Key Indicators

- S3 bucket URL in JavaScript: s3.amazonaws.com, s3.region.amazonaws.com
- GCS: storage.googleapis.com, storage.cloud.google.com
- Azure: blob.core.windows.net, azureedge.net
- CDN: cloudfront.net, fastly.net, azureedge.net, cdn.example.com
- Container: *.compute.amazonaws.com (default EC2 hostname)
- Kubernetes: *.elb.amazonaws.com, *.aks.microsoft.com

## Stop Conditions

- Open bucket: confirm read access with a HEAD request on a single object, stop
- Metadata endpoint reachable via SSRF: confirm with a single IMDS request, stop
- Exposed Docker socket: confirm with GET /version, stop (never execute containers)
- Never: pivot from cloud access to customer data access beyond minimal proof
