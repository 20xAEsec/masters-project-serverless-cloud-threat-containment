import json
import boto3
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from botocore.exceptions import ClientError

def get_secret():
    secret_name = "capstone-secrets"
    region_name = "us-west-2"

    session = boto3.session.Session()
    client = session.client(service_name='secretsmanager', region_name=region_name)

    try:
        get_secret_value_response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        raise e

    secret = get_secret_value_response['SecretString']
    return secret

# Initialize AWS clients
lambda_client = boto3.client('lambda')
dynamodb = boto3.resource('dynamodb')

# DynamoDB table name
secret = json.loads(get_secret())
TABLE_NAME = secret['DYNAMODB_TABLE']


# IN PROGRESS
# PLAYBOOKS TO BE STORED AND RETRIEVED FROM DYNAMODB
def get_playbook_text(alert_ip, alert_type, group_name):
    
    playbook_text = "Default Playbook Text\n"
    
    if alert_type == "open_database":
        playbook_text = f"""Remediate the {alert_type} alert for the group {group_name} by following these instructions:\nOPEN DATABASE INSTRUCTIONS \n""" 
    elif alert_type == "vulnerable_service":
        playbook_text = f"""Remediate the {alert_type} alert for the group {group_name} by following these instructions:\nVULNERABLE SERVICE INSTRUCTIONS\n"""
    
    secret = json.loads(get_secret())
    lambda_url = secret['RECOVER_LAMBDA_URL']
  
    # Append trigger-URL for Recovery Lambda to end of email
    playbook_text += f"{lambda_url}/recover?ip={alert_ip}"
    return playbook_text

# Uses Google SMTP to send alert emails from a personal account
# See link for more information - https://support.google.com/accounts/answer/185833?hl=en
def send_email(alert_ip, alert_type, group_name):
    try:
        email_secret = json.loads(get_secret())
        GMAIL_USER = email_secret['GMAIL_USER']
        GMAIL_APP_PASSWORD = email_secret['GMAIL_APP_PASSWORD']
        to_email = email_secret['RECIPIENT_EMAIL']
        subject = "CLOUD SECURITY NOTIFICATION FROM SHODAN"

        body = get_playbook_text(alert_ip, alert_type, group_name)

        msg = MIMEMultipart()
        msg['From'] = GMAIL_USER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
            server.send_message(msg)

        return {
            'statusCode': 200,
            'body': f'Email sent to {to_email}'
        }

    except Exception as e:
        return {
            'body': f'ERROR SENDING EMAIL - {e}'
        }

# For processing into DynamoDB
# Specific format expected and required
def flatten_json(y):
    """
    Flattens nested JSON into a flat dict.
    Example: {'location': {'city': 'LA'}} => {'location_city': 'LA'}
    """
    out = {}

    def flatten(x, name=''):
        if isinstance(x, dict):
            for a in x:
                flatten(x[a], f"{name}{a}_")
        elif isinstance(x, list):
            out[name[:-1]] = ','.join(str(i) for i in x)
        else:
            out[name[:-1]] = x

    flatten(y)
    return out

def lambda_handler(event, context):
    try:
        # 1) Parse the payload
       # Ensure its the right format, use this to account for discrepancies between test & live data
        if isinstance(event, str):
            payload = json.loads(event)
        elif isinstance(event, dict) and 'body' in event:
            body = event['body']
            payload = json.loads(body) if isinstance(body, str) else body
        else:
            payload = event
        
        # for debugging
        #print(f"PAYLOAD RECEIVED: {payload}")

        # 2) Extract IP address
        alert_ip = payload.get('ip_str')
        if not alert_ip:
            raise ValueError("No 'ip_str' found in event payload")

        print(f"Updating DynamoDB for IP: {alert_ip}")

          # 3) Flatten payload for DynamoDB update
        flat_payload = flatten_json(payload)
        flat_payload['Alert'] = True  # explicitly set Alert to True

        # Saves SecurityGroup settings for alerting resource to DynamoDB for reference later when restoring
        # 3A) Get current Security Group(s) for the instance matching this IP
        ec2_client = boto3.client('ec2')

        # Find the EC2 instance with the public IP in the alert
        instances = ec2_client.describe_instances(
            Filters=[
                {'Name': 'ip-address', 'Values': [alert_ip]}
            ]
        )

        security_groups = []
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                for sg in instance['SecurityGroups']:
                    security_groups.append({
                        'GroupId': sg['GroupId'],
                        'GroupName': sg['GroupName']
                    })

        print(f"Security Groups for {alert_ip}: {security_groups}")

        # 3B) Add SecurityGroup info to flat_payload
        flat_payload['SecurityGroup'] = security_groups

         # 3C) Quarantine: change Security Group to the quarantine SG
        quarantine_sg_id = 'sg-0c36d0b65832638a4'
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                print(f"Quarantining instance {instance_id}")

                ec2_client.modify_instance_attribute(
                    InstanceId=instance_id,
                    Groups=[quarantine_sg_id]
                )

        # 4) Build UpdateExpression dynamically with placeholders
        update_clauses = []
        expression_attr_names = {}
        expression_attr_values = {}

        for k, v in flat_payload.items():
            if k == 'ip_str':
                continue  # skip, this is the primary/partition key
            placeholder_name = f"#{k}"
            placeholder_value = f":{k}"
            update_clauses.append(f"{placeholder_name} = {placeholder_value}")
            expression_attr_names[placeholder_name] = k
            expression_attr_values[placeholder_value] = v

        update_expression = "SET " + ", ".join(update_clauses)
        
      
        # 5) Perform update with ExpressionAttributeNames too
        table = dynamodb.Table(TABLE_NAME)
        response = table.update_item(
            Key={'IPAddress': alert_ip},
            UpdateExpression=update_expression,
            ExpressionAttributeNames=expression_attr_names,
            ExpressionAttributeValues=expression_attr_values,
            ReturnValues="UPDATED_NEW"
        )

        print(f"DynamoDB Update Response: {response}")

        # 6) Send remediation email
        group_name = payload.get('_shodan', {}).get('alert', {}).get('name', '')
        alert_type = payload.get('_shodan', {}).get('alert', {}).get('trigger', '')
        email_result = send_email(alert_ip, alert_type, group_name)
        print(f"Email result: {email_result}")

        return {
            'statusCode': 200,
            'body': json.dumps({'message': f"Alert updated and data stored for IP {alert_ip}"})
        }

    except Exception as e:
        print(f"Error: {e}")
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
