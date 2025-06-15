## 🔑 IAM Policies (Least Privilege)

Below are the recommended **inline IAM policies** for each Lambda execution role.  
Replace `YOUR_ACCOUNT_ID` with your actual AWS account ID and 'TABLE_NAME' with your DynamoDB table, and 'SECRET_NAME' with the secret key in AWS Secrets Manager

---

### 📌 **1️⃣ GetPublicIps-Lambda**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:DescribeAddresses",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeNatGateways",
        "rds:DescribeDBInstances",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:PutItem",
        "dynamodb:UpdateItem"
      ],
      "Resource": "arn:aws:dynamodb:us-west-2:YOUR_ACCOUNT_ID:table/<TABLE_NAME>"
    }
  ]
}
```
### 📌 **2️⃣ OnboardShodan-Lambda**

This Lambda reads the public IP inventory from DynamoDB and subscribes each IP to **Shodan Monitor** for continuous monitoring.

**Recommended Inline Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:Scan",
        "dynamodb:Query",
        "dynamodb:GetItem"
      ],
      "Resource": "arn:aws:dynamodb:us-west-2:YOUR_ACCOUNT_ID:table/<TABLE_NAME>"
    }
  ]
}
```
  
  
### 📌 **3️⃣ SaveAlert-Contain-Remediate-Lambda**

This Lambda handles incoming Shodan alerts: it saves alert data to DynamoDB, retrieves the affected resource, stores its security group, quarantines the resource, and sends an email with a recovery link.

**Recommended Inline Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:UpdateItem",
        "dynamodb:PutItem",
        "dynamodb:GetItem"
      ],
      "Resource": "arn:aws:dynamodb:us-west-2:YOUR_ACCOUNT_ID:table/<TABLE_NAME>"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:ModifyInstanceAttribute"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:us-west-2:YOUR_ACCOUNT_ID:secret:<SECRET_NAME>*"
    }
  ]
}
```


  
### 📌 **4️⃣ RecoverInstance-Lambda**

This Lambda restores the original security group for a quarantined resource when the recovery link is clicked. It reads the backup from DynamoDB, modifies the instance security group, and updates the incident status.

**Recommended Inline Policy:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:UpdateItem"
      ],
      "Resource": "arn:aws:dynamodb:us-west-2:YOUR_ACCOUNT_ID:table/<TABLE_NAME>"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:ModifyInstanceAttribute"
      ],
      "Resource": "*"
    }
  ]
}
```


