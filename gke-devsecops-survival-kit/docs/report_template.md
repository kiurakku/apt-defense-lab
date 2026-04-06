# Lab Report — DevSecOps GKE Survival Kit

## 1. Executive Summary

<!-- 3 sentences: simulated Russian APT targeting crypto-mining and cloud penetration; tactics include /tmp “magic” files and C&C on a specific port; stolen engineer SA keys blocked → federation required. -->

## 2. Infrastructure Overview

<!-- Placeholder: screenshot from GCP Console (GKE + BigQuery + IAM). -->

### ASCII architecture (paste from README or draw your own)

```
(TODO: diagram)
```

## 3. Task 1: Container Escape & Master Plane Crash

### 3.1 Container escape

- **What we did:**  
  <!-- Short description: privileged pod, escape.sh, vulnerable-pool node. -->
- **Screenshot placeholder:**  
  <!-- Attach terminal / kubectl evidence. -->
- **CVE reference:**  
  <!-- e.g. CVE-2022-0492, link to NVD + GKE bulletin. -->
- **Mitigation:**  
  <!-- PSS, no privileged, upgrades, Shielded VM. -->

### 3.2 Master plane / API server stress

- **What we did:**  
  <!-- dos_apiserver.sh ConfigMap flood; optional bulletin CVE stub. -->
- **Screenshot placeholder:**  
  <!-- API latency / control plane metrics. -->
- **CVE reference:**  
  <!-- If applicable from bulletins. -->
- **Mitigation:**  
  <!-- Quotas, APF, admission, upgrades. -->

## 4. Task 2: Trivy Pipeline

### 4.1 Trivy operator deployment

- **Proof:**  
  <!-- helm list, pods in trivy-system, sample VulnerabilityReport. -->

### 4.2 BigQuery raw logs

- **Screenshot placeholder:**  
  <!-- raw_compressed_logs rows. -->

### 4.3 BigQuery clean vulnerabilities

- **Screenshot placeholder:**  
  <!-- clean_vulnerabilities after parse_trivy_bq.py. -->

### 4.4 Compression explanation

<!-- Trivy operator serializes VulnerabilityReport to JSON, gzips, base64-encodes, stores in CR annotation/ConfigMap — cite operator source (pkg/compress). -->

## 5. Task 3: GitHub Action Exploit

### 5.1 Vulnerable workflow

- **Explanation:**  
  <!-- pull_request from fork + WIF without ref restriction. -->

### 5.2 Token exfiltration proof

- **Screenshot / redacted log:**  
  <!-- Do not paste live tokens. -->

### 5.3 Hardened fix

- **Explanation:**  
  <!-- push to main, attribute_condition, least privilege. -->

## 6. Defensive Controls Implemented

### 6.1 Falco rules triggered

- **Which rules:**  
  <!-- APT tmp file drop, reverse shell port, privileged mount. -->

### 6.2 NetworkPolicy egress

- **Behavior:**  
  <!-- deny default; allow 443/53 only; C&C port absent. -->

### 6.3 WIF subject restriction

- **Terraform / provider settings:**  
  <!-- attribute_condition, repository binding. -->

## 7. Recommendations

- Zero Trust for CI/CD and human access  
- Immutable infrastructure and image signing  
- Workload Identity best practices (narrow principalSet, separate plan/apply SAs)

---

**Footer:** Share this document with view access and paste the link in your submission.
