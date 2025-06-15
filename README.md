# 🔒 Serverless Cloud Threat Response
## In Progress; Estimated Completion - July 2025
This repository contains a serverless, automated solution for identifying, detecting, containing, and recovering from cloud security incidents on AWS. Built as a **Masters of Cybersecurity and Information Assurance Capstone Project for WGU**, it demonstrates practical cloud security automation and incident response.

---

## 🚀 Project Overview

This project automates:

- ✅ Continuous monitoring of your AWS external attack surface using **Shodan Monitor**
- ✅ Automated containment when a threat is detected
- ✅ Immediate email alert with remediation instructions and a **one-click secure recovery link**
- ✅ Fully automated recovery that restores the original configuration

---

## 📂 Included Lambda Functions

| Lambda | Purpose |
| ------ | ------- |
| **1️⃣ `GetPublicIps-Lambda`** | Queries your AWS account for all public IP addresses and saves them to the `PublicIPAddresses` DynamoDB table. |
| **2️⃣ `OnboardShodan-Lambda`** | Subscribes discovered IP addresses to Shodan Monitor with configured network alerts. |
| **3️⃣ `TrackAlert-Contain-EmailRemediate-Lambda`** | Triggered by a Shodan alert; Saves alert to DynamoDB; Emails playbook with remediation instructions to account owner, enabling automatic restoration of security groups with a click once completed.
  - Saves the alert to DynamoDB  
  - Retrieves the affected resource  
  - Stores its current Security Group configuration  
  - Switches the Security Group to a restrictive **quarantine SG**  
  - Sends an email with remediation instructions and a **one-click recovery link** |
| **4️⃣ `RecoverInstance-Lambda`** | Triggered when a user clicks the link in the alert email:  
  - Reads the original Security Group info from DynamoDB  
  - Restores it to the resource  
  - Marks the incident as **remediated** |

---

## 🗂️ AWS Resources Used

- **AWS Lambda** — all functions run serverlessly.
- **Amazon DynamoDB** — stores IP addresses, alert data if applicable, security group backups, and incident status.
- **Amazon EC2** — the target resources for containment and recovery.
- **AWS API Gateway** — exposes `RecoverInstance-Lambda` as a secure HTTPS endpoint.
- **AWS Secrets Manager** — securely stores email and recovery link configuration.
- **Shodan Monitor** — external monitoring for cloud-exposed resources.

---

## ⚙️ Key Configuration

| Name | Purpose |
| ---- | ------- |
| **DynamoDB Table** | `PublicIPAddresses` with Partition Key: `IPAddress`. Other attributes are added dynamically (`ARN`, `Alert`, `RemediationStatus`, `SecurityGroup`, etc). |
| **Quarantine SG** | A restrictive security group (`sg-xxxxxxxx`) that blocks inbound/outbound traffic. |
| **Secrets Manager** | Stores `GMAIL_USER`, `GMAIL_APP_PASSWORD`, `RECIPIENT_EMAIL`, `RECOVER_LAMBDA_URL` (your API Gateway URL). |

---

## ✉️ How Email Recovery Works

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

## ✅ IAM Permissions

All Lambdas use least privilege:

- **EC2:** `DescribeInstances`, `ModifyInstanceAttribute`
- **DynamoDB:** `GetItem`, `PutItem`, `UpdateItem`
- **Secrets Manager:** `GetSecretValue`
- **API Gateway:** triggers `RecoverInstance-Lambda`

---

## 🚀 Deployment Steps

1. **Clone the repo**

   ```bash
   git clone https://github.com/<your-username>/serverless-cloud-threat-response.git
   cd serverless-cloud-threat-response
