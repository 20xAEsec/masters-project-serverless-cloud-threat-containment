# Serverless Cloud Threat Response Automation
This repository contains a serverless, automated solution for identifying, detecting, containing, and recovering from cloud security incidents on AWS. Built as a **Masters of Cybersecurity and Information Assurance Capstone Project**, it demonstrates practical cloud security automation and incident response, performing actions for all core phases of NIST's Cybersecurity Framework (Preparation, Detection and Analysis, Containment/Eradication/Recovery, and Post-Incident Activity).

---

## Project Overview

This project automates:

- ✅ Continuous monitoring of your AWS external attack surface using **Shodan Monitor**
- ✅ Automated containment when a threat is detected
- ✅ Immediate email alert with remediation instructions and a **one-click secure recovery link**
- ✅ Fully automated recovery that restores the original configuration

---

## Architecture (Click to Expand)
![Diagram](https://i.ibb.co/Mk9QfCTj/Shodan-Diagram-White-drawio.png)

## Included Lambda Functions

| Lambda | Purpose |
| ------ | ------- |
| **1️⃣ `GetPublicIps-Lambda`** | Queries your AWS account for all public IP addresses and saves them to your DynamoDB table. |
| **2️⃣ `OnboardShodan-Lambda`** | Triggered when new IPs are added to DynamoDB. Checks if each IP is already covered by a Shodan Monitor network alert group. If not, it creates a new group named after the resource and configures recommended alert triggers to ensure continuous monitoring. |
| **3️⃣ `AlertContain-Lambda`** | Triggered by a Shodan alert. Saves the alert to DynamoDB, retrieves the affected resource, stores its current Security Group configuration, switches the Security Group to a restrictive **quarantine SG**, and sends an email with remediation instructions plus a **one-click recovery link**. |
| **4️⃣ `RecoverInstance-Lambda`** | Triggered when a user clicks the recovery link in the alert email. Reads the original Security Group info from DynamoDB, restores it to the affected resource, and marks the incident as **remediated**. |


## AWS Resources Used

- **AWS Lambda** — all functions run serverlessly.
- **Amazon DynamoDB** — stores IP addresses, alert data if applicable, security group backups, and incident status.
- **Amazon EC2** — the target resources for containment and recovery.
- **AWS API Gateway** — exposes `RecoverInstance-Lambda` as a secure HTTPS endpoint.
- **AWS Secrets Manager** — securely stores email and recovery link configuration.
- **Shodan Monitor** — external monitoring for cloud-exposed resources.

---

## Key Configuration

| Name | Purpose |
| ---- | ------- |
| **DynamoDB Table** | `PublicIPAddresses` with Partition Key: `IPAddress`. Stream Configured between this table and OnboardShodan-Lambda. Other attributes are added dynamically (`ARN`, `Alert`, `RemediationStatus`, `SecurityGroup`, etc). |
| **Quarantine SG** | A restrictive security group that blocks all inbound/outbound traffic. |
| **Secrets Manager** | Stores `GMAIL_USER`, `GMAIL_APP_PASSWORD`, `RECIPIENT_EMAIL`, `RECOVER_LAMBDA_URL` (your API Gateway URL). |

---

## How Email Remediation Works

When containment occurs:
- The `SaveAlert-Contain-Remediate` Lambda sends an email with:
  - A clear remediation playbook
  - A clickable link:
    ```
    https://<API_GATEWAY_URL>/recover?ip=<ALERT_IP>
    ```
- Clicking the link triggers `RecoverInstance-Lambda`, which:
  - Looks up the saved Security Group
  - Restores the resource to its original configuration
  - Marks the incident as complete

---

## IAM Permissions

All Lambdas adhere to least privilege: see /lambdas for complete IAM policies

- **EC2:** `DescribeInstances`, `ModifyInstanceAttribute`
- **DynamoDB:** `GetItem`, `PutItem`, `UpdateItem`
- **Secrets Manager:** `GetSecretValue`
- **API Gateway:** triggers `RecoverInstance-Lambda`

---

## Self Deployment (IaC)
Use the Cloudformation Template in `template.yaml` to deploy to your own AWS Account, with all required resources.  
Follow contained instructions to name your resources and fill in placeholders where requested.
