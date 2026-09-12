---
layout: post
title: "Cloud Incident Response: IAM Privilege Escalation"
date: 2026-09-11
---

*Part of an ongoing home lab series while pursuing Cloud ecurity certifications.*

## Background

After some time doing Incident Response, I've gained an interest into cloud security, specifically, learning to think like both the attacker and the defender in AWS and Azure environments. This post walks through the first exercise in that process: exploiting a real IAM misconfiguration using [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), Rhino Security Labs' "vulnerable by design" AWS deployment tool.

The goal was to close the loop an IR analyst actually cares about: what happened, and what evidence did it leave behind?

## Lab Setup

- Local Kali Linux VM (VirtualBox) as the attacker workstation
- Real AWS free-tier account, with logging established before deploying anything vulnerable:
  - CloudTrail (API activity logging)
  - AWS Config (configuration change tracking)
  - GuardDuty (pending account activation)
- CloudGoat 2.5.0 deployed via Poetry, targeting the `iam_privesc_by_rollback` scenario

Standing up detection first, then attacking,  you can't investigate what you never logged.

## The Vulnerability: Policy Version Rollback

CloudGoat deployed a low-privilege IAM user (`raynor`) with what looked like a minimal, read-only policy. But AWS IAM policies keep version history up to five versions per managed policy and old versions don't disappear when a policy is updated unless someone explicitly deletes them.

Inspecting the policy's version history revealed the problem immediately:

| Version | Permissions |
|---|---|
| v1 (default) | `iam:Get*`, `iam:List*`, **`iam:SetDefaultPolicyVersion`** |
| v2 | Deny-all with an IP condition (decoy) |
| v3 | `"Action": "*", "Resource": "*"` — full admin |
| v4 | Narrow IAM read access, expired time condition (decoy) |
| v5 | S3 read-only |

The current policy (v1) looked harmless on its own. But it granted one specific, easy-to-overlook permission: `iam:SetDefaultPolicyVersion` — the ability to change *which version* of the policy is active, without needing permission to edit the policy's content at all.

That's the entire vulnerability. Nobody needs to write a new malicious policy or escalate through some elaborate chain, an old, more permissive version was just sitting there, waiting to be reactivated.

## The Exploit

From the low-privilege `raynor` credentials:

```bash
aws iam set-default-policy-version \
  --policy-arn arn:aws:iam::<account-id>:policy/cg-raynor-policy-<id> \
  --version-id v3 \
  --profile raynor
```

One command, and `raynor` now has full administrative access, confirmed by listing every bucket in the account, something the original permission set never allowed:

```bash
aws s3 ls --profile raynor
```

## Reading the Evidence

This is the part I actually care most about. Pulling the corresponding CloudTrail event afterward showed exactly what a real investigation would show:

```json
{
  "eventName": "SetDefaultPolicyVersion",
  "userIdentity": {
    "userName": "raynor-<id>"
  },
  "sourceIPAddress": "<attacker IP>",
  "userAgent": "aws-cli/2.36.17 ... os/linux ... kali-amd64",
  "requestParameters": {
    "policyArn": "arn:aws:iam::<account-id>:policy/cg-raynor-policy-<id>",
    "versionId": "v3"
  }
}
```

A few things stand out, in the order I'd flag them in a real investigation:

1. **`SetDefaultPolicyVersion` as the event name.** This API call is rare in legitimate workflows. Seeing it at all is a signal worth investigating on its own.
2. **`versionId: v3`.** Meaningless without context but if you've already reviewed the policy's version history (as any thorough investigation should), you immediately recognize v3 as the full-admin version. This single field tells you the outcome of the action without needing to check anything else.
3. **The user agent literally contains `kali-amd64`.** In a real environment, this is about as loud a signal as it gets — legitimate business workflows don't run AWS CLI from a penetration testing distribution. This is the kind of small detail that's easy to miss if you're only skimming event names, but immediately actionable once you know to look for it.
4. **Source IP correlation.** Matching the source IP against known-good ranges (VPN, office egress, etc.) is a standard IR step, and it's just as relevant in cloud investigations as it is in traditional network forensics.

## Takeaways

- **Old policy versions are a real, underrated attack surface.** IAM policies default to keeping up to five versions, and cleanup isn't automatic. A single overlooked permission (`iam:SetDefaultPolicyVersion`) turned a "read-only" identity into a full admin.
- **Logging before attacking matters.** Because CloudTrail was already running, this entire chain was fully reconstructable after the fact — exactly the workflow a real detection engineer or IR analyst would rely on.
- **Small details carry a lot of signal.** The user-agent string alone would be enough to open an investigation in a real SOC. Cloud security work has different artifacts than traditional endpoint/network IR, but the underlying instinct — look for what doesn't belong — transfers directly.

## Next Up

- Retrying GuardDuty once the AWS account finishes activation, and wiring EventBridge to alert on findings automatically
- A second CloudGoat scenario, likely `cloud_breach_s3` or `iam_privesc_by_ec2`
- Standing up the Azure equivalent with Azure Goat
- Eventually rebuilding these scenarios with hand-written Terraform once I've seen enough of CloudGoat's own IaC to understand the patterns
