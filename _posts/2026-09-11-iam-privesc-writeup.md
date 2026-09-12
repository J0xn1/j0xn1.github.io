---
layout: post
title: "Cloud Incident Response: IAM Privilege Escalation - Jon"
date: 2026-09-11
---

Part of an ongoing home lab series while pursuing Cloud Security Specialty certifications.

## Background

After some time doing Incident Response, I've gained an interest into cloud security, learning to think like both the attacker and the defender in AWS and Azure environments. I built a home lab in AWS and Azure where I can practice both attacking and defending cloud environments.

For this first exercise, I used CloudGoat (a tool from Rhino Security Labs that deploys intentionally vulnerable AWS environments) to run a real IAM privilege escalation attack. There are a few blog posts out there already regarding this exercise but I wanted to reconstruct it in my own environment. The goal wasn't just to run the exploit, I wanted to actually go back afterward and see what evidence it left in the logs.

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
- Eventually rewriting these scenarios in my own Terraform, once I've seen enough of CloudGoat's setup to understand the patterns.
