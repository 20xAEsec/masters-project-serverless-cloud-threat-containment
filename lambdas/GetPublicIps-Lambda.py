import boto3
import socket
import json
import boto3
from botocore.exceptions import ClientError


def get_secret():

    secret_name = "capstone-secrets"
    region_name = "us-west-2"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = json.loads(get_secret_value_response['SecretString'])
    return secret


# Initialize AWS clients
ec2 = boto3.client('ec2')
dynamodb = boto3.resource('dynamodb')

# DynamoDB table name (replace with your actual table name)
TABLE_NAME = get_secret()['DYNAMODB_TABLE']

def lambda_handler(event, context):
    # Describe all EC2 instances
    response = ec2.describe_instances()
    
    # Reference your DynamoDB table
    table = dynamodb.Table(TABLE_NAME)
    account_id = get_secret()['AWS_ACCOUNT_ID']

    # Iterate through reservations and instances
    for reservation in response['Reservations']:
        for instance in reservation['Instances']:
            # Only proceed if the instance has a public IP
            if 'PublicIpAddress' in instance:
                public_ip = instance['PublicIpAddress']
                instance_id = instance['InstanceId']
                arn = f'arn:aws:ec2:us-west-2:{account_id}:instance/{instance_id}'

                # Put item into DynamoDB
                table.put_item(
                    Item={
                        'IPAddress': public_ip,
                        'ARN': arn,
                        'Alert': False,  # default
                        'RemediationStatus': 'Pending'  # default
                    }
                )
                #print the contents of the added record
                print(f'Added record: {public_ip}, {arn}') 


    return {
        'statusCode': 200,
        'body': f'Successfully saved public IPs to DynamoDB table {TABLE_NAME}'
    }
