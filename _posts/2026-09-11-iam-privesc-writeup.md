---
layout: post
title: "Cloud Incident Response: IAM Privilege Escalation - Jon"
date: 2026-09-11
---

Part of an ongoing home lab series while pursuing AWS Solutions Architect and Security Specialty certifications.

## Background

After some time doing Incident Response, I've gained an interest into cloud security, learning to think like both the attacker and the defender in AWS and Azure environments. I built a home lab in AWS and Azure where I can practice both attacking and defending cloud environments.

For this first exercise, I used CloudGoat (a tool from Rhino Security Labs that deploys intentionally vulnerable AWS environments) to run a real IAM privilege escalation attack. The goal wasn't just to run the exploit, I wanted to actually go back afterward and see what evidence it left in the logs.

## Lab Setup

- Kali Linux VM (VirtualBox) as my attack machine
- A real AWS account, free tier
- Logging set up before I touched anything vulnerable: CloudTrail, AWS Config, and GuardDuty (still waiting on account activation)
- CloudGoat 2.5.0, using the `iam_privesc_by_rollback` scenario

I set up logging first then attacking.

## The Vulnerability

I used CloudGoat to deploy a low-privilege IAM user called `raynor`, with a pretty limited, read-only policy attached. But IAM policies in AWS keep version history, up to 5 versions and old versions don't get deleted automatically when a policy changes.

When I looked at the version history for raynor's policy, here's what I found:

| Version | Permissions |
|---|---|
| v1 (default) | `iam:Get*`, `iam:List*`, and `iam:SetDefaultPolicyVersion` |
| v2 | Deny-all with an IP condition |
| v3 | Full admin — `"Action": "*", "Resource": "*"` |
| v4 | Narrow IAM read access, expired |
| v5 | S3 read-only |

The current policy (v1) looked harmless by itself. But it gave raynor one permission: `iam:SetDefaultPolicyVersion` — the ability to switch which version of the policy is active, without needing permission to actually edit the policy.

That's the whole vulnerability. An old admin-level policy version was just sitting there, and raynor had exactly the permission needed to bring it back.

## Running the Exploit

Using raynor's credentials:

```bash
aws iam set-default-policy-version \
  --policy-arn arn:aws:iam::<account-id>:policy/cg-raynor-policy-<id> \
  --version-id v3 \
  --profile raynor
```

One command, and raynor went from barely-read-only to full admin. I confirmed it by listing every S3 bucket in the account, something raynor definitely shouldn't have been able to do before:

```bash
aws s3 ls --profile raynor
```

## Checking the Logs

 I pulled up CloudTrail afterward and found the exact event the exploit generated:

```json
{
  "eventName": "SetDefaultPolicyVersion",
  "userIdentity": {
    "userName": "raynor-<id>"
  },
  "sourceIPAddress": "<my IP>",
  "userAgent": "aws-cli/2.36.17 ... os/linux ... kali-amd64",
  "requestParameters": {
    "policyArn": "arn:aws:iam::<account-id>:policy/cg-raynor-policy-<id>",
    "versionId": "v3"
  }
}
```

A few things stood out to me, in the order I'd probably notice them if I saw this in a real investigation:

1. **`SetDefaultPolicyVersion` as the event name.** Just seeing it happen at all is worth a second look.
2. **`versionId: v3`.** Doesn't mean much on its own, but since I'd already looked at the policy's version history, I immediately knew v3 was the admin version. That one field basically tells you what happened.
3. **The user agent says `kali-amd64`.** In a real company, this is a huge red flag; nobody's legitimate day-to-day work runs through Kali Linux besides red teamers.
4. **Source IP.** Matching this against known-good IP ranges is a normal step in any investigation, cloud or not.

## What I Took Away From This

- Old IAM policy versions are a real attack surface that's easy to overlook. AWS keeps up to 5 versions by default, and nobody cleans them up automatically.
- Setting up logging before attacking anything made the whole thing reconstructable afterward.
- Small details carry a lot of weight. That user-agent string alone would be enough to start an investigation in a real environment.

## What's Next

- Retrying GuardDuty once my AWS account finishes activating, and hooking up EventBridge to alert automatically on findings
- Trying another CloudGoat scenario — probably `cloud_breach_s3` or `iam_privesc_by_ec2`
- Building the Azure side of this lab with Azure Goat
- Eventually rewriting these scenarios in my own Terraform, once I've seen enough of CloudGoat's setup to understand the patterns









---
layout: post
title: "Cloud Incident Response: IAM Privilege Escalation - Jon"
date: 2026-09-11
---

*Part of an ongoing home lab series while pursuing Cloud Security certifications.*

## Background

After some time doing Incident Response, I've gained an interest into cloud security, learning to think like both the attacker and the defender in AWS and Azure environments. This post walks through the first exercise that I did: exploiting a real IAM misconfiguration using [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), Rhino Security Labs' "vulnerable by design" AWS deployment tool.

The goal was to close the loop an IR analyst actually cares about: what happened, and what evidence did it leave behind?

## Lab Setup

- Local Kali Linux VM (VirtualBox) as the attacker workstation
- Real AWS free-tier account, with logging established before deploying anything vulnerable:
  - CloudTrail (API activity logging)
  - AWS Config (configuration change tracking)
  - GuardDuty (pending account activation)
- CloudGoat 2.5.0 deployed via Poetry, targeting the `iam_privesc_by_rollback` scenario

Standing up detection first, then attacking.

## The Vulnerability: Policy Version Rollback

CloudGoat deployed a low-privilege IAM user (`raynor`) with what looked like a minimal, read-only policy. But AWS IAM policies keep version history up to five versions per managed policy and old versions don't disappear when a policy is updated unless someone explicitly deletes them.

Analyzing the policy's version history revealed the problem immediately:

| Version | Permissions |
|---|---|
| v1 (default) | `iam:Get*`, `iam:List*`, **`iam:SetDefaultPolicyVersion`** |
| v2 | Deny-all with an IP condition (decoy) |
| v3 | `"Action": "*", "Resource": "*"` — full admin |
| v4 | Narrow IAM read access, expired time condition (decoy) |
| v5 | S3 read-only |

The current policy (v1) looked harmless on its own. But it granted one specific permission: `iam:SetDefaultPolicyVersion`  the ability to change which version of the policy is active, without needing permission to edit the policy's content.

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

 Pulling the CloudTrail event afterward showed exactly what a real investigation would show:

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

This is the order I'd flag them in a real investigation:

1. **`SetDefaultPolicyVersion` as the event name.** This API call is rare in legitimate workflows. Seeing it at all is worth investigating.
2. **`versionId: v3` If you've already reviewed the policy's version history, you immediately recognize v3 as the full admin version. This field tells you the outcome of the action without needing to check anything else.
3. **The user agent contains `kali-amd64`.** In a real environment, this is about as loud a signal as it gets. Kali Linux is a giveaway. This is easy to miss if you're only skimming event names.
4. **Source IP correlation.** Matching the source IP against known-good ranges is a standard IR thing, and it's just as relevant in cloud investigations as it is in traditional network forensics.

## Takeaways

- **Old policy versions are a real, underrated attack surface.** IAM policies default to keeping up to five versions, and cleanup isn't automatic. An overlooked permission (`iam:SetDefaultPolicyVersion`) turned a read-only identity into a full admin.
- **Logging before attacking matters.** Because CloudTrail was already running, this entire chain was fully reconstructable after the fact.
- **Small details carry a lot of signal.** The user-agent string alone would be enough to open an investigation in a real environment. Cloud security work has different artifacts than traditional IR, but the instinct and what to look for transfers directly.

## Next Up

- Retrying GuardDuty once the AWS account finishes activation, and wiring EventBridge to alert on findings automatically
- A second CloudGoat scenario, likely `cloud_breach_s3` or `iam_privesc_by_ec2`
- Standing up the Azure equivalent with Azure Goat
- Eventually rebuilding these scenarios with hand-written Terraform once I've seen enough of CloudGoat's own IaC to understand the patterns
