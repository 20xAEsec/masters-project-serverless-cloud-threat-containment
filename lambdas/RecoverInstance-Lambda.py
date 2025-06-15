import json
import boto3

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

# DynamoDB table name (replace with your actual table name (SECRET))
TABLE_NAME = get_secret()['DYNAMODB_TABLE']

def lambda_handler(event, context):
    try:
        # Extract IP from query string parameters
        ip = event['queryStringParameters']['ip']
        print(f"Recover request for IP: {ip}")

        # Look up the original Security Groups from DynamoDB
        table = dynamodb.Table(TABLE_NAME)
        response = table.get_item(Key={'IPAddress': ip})
        item = response.get('Item')

        if not item or 'SecurityGroup' not in item:
            return {
                'statusCode': 400,
                'body': f"No saved SecurityGroup found for IP {ip}."
            }

        security_groups = item['SecurityGroup']

        # ✅ Auto-detect if it's raw DynamoDB AttributeValue or plain JSON:
        decoded_sg = []
        for sg in security_groups:
            if isinstance(sg, dict) and 'M' in sg:
                # It's AttributeValue format -> decode it
                sg_map = sg['M']
                decoded_sg.append({
                    'GroupId': sg_map['GroupId']['S'],
                    'GroupName': sg_map['GroupName']['S']
                })
            else:
                # It's already plain JSON
                decoded_sg.append(sg)

        original_sg_ids = [sg['GroupId'] for sg in decoded_sg]
        print(f"Decoded SG IDs to restore: {original_sg_ids}")
        print(f"Original SGs: {original_sg_ids}")

        # Find instance by IP
        instances = ec2.describe_instances(
            Filters=[{'Name': 'ip-address', 'Values': [ip]}]
        )

        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                print(f"Restoring SG for instance {instance_id} to {original_sg_ids}")

                ec2.modify_instance_attribute(
                    InstanceId=instance_id,
                    Groups=original_sg_ids
                )

        # update DynamoDB to mark alert as remediated
        table.update_item(
            Key={'IPAddress': ip},
            UpdateExpression="SET RemediationStatus = :status",
            ExpressionAttributeValues={':status': 'Complete'}
        )

        return {
            'statusCode': 200,
            'body': f"Security Groups restored for instance with IP {ip}."
        }

    except Exception as e:
        print(f"Error: {e}")
        return {
            'statusCode': 500,
            'body': f"Error restoring Security Groups: {e}"
        }
