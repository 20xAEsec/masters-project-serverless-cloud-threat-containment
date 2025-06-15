import json
import requests
import boto3
import time
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key

# Input: 
    # api_key - Shodan API Key
# Return Value:
    # Python Dict mapping groupName → groupID

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

def get_group_listing(api_key):
    url = f'https://api.shodan.io/shodan/alert/info?key={api_key}'
    time.sleep(1)
    response = requests.get(url) # get list of configured network alert groups
    result_dict = {}
    if response. status_code == 200:
        network_alerts = response.json ()
        for alert in network_alerts:  # Iterate through the list of network alerts
            print(json.dumps(alert, indent=3))
            group_name = alert['name']
            group_id = alert['id']
            result_dict[group_name] = group_id # and create groupName → group ID mapping

    return result_dict

# returns boolean
def check_group_for_ip(ip_address, group_id, api_key):
    group_url = f'https://api.shodan.io/shodan/alert/{group_id}/info?key={api_key}'
    time.sleep (1)
    response = requests.get(group_url)
    #print (group_url)
    # Check if the API request was successful
    if response.status_code == 200:
        try:
            ip_list = response. json()["filters"]["ip"]  # Parse the JSON response; gets IP's in Group
            for ip_val in ip_list:
                if ip_address in ip_val:
                     return True
            
            return False
        
        except Exception as e:
            print(f"Error checking group for IP - {e}")

# Create Network Alert group in Shodan Monitor
def create_ip_group(api_key, group_name, ip_address) :
    url = f'https://api.shodan.io/shodan/alert?key={api_key}'
    payload = {
        "name": group_name,
        "filters": {
        "ip": ip_address #ip address for resource
        }
    }
    time.sleep(1)
    response = requests.post(url, json=payload)

    if __debug__:
        print("create_ip_group status code - " + str(response.status_code) )
    
    # If successful, get and return the Group ID, otherwise return None
    if response.status_code == 200:
        print (f"IP group created - HTTP {response.status_code}")
        return response. json()['id']
    else:
        return None

# Configures Network Group with all alerts
def add_alerts_to_group(api_key, group_id):
    trigger = "new_service,malware,uncommon,open_database,ssl_expired,vulnerable"
    url=f'https://api.shodan.io/shodan/alert/{group_id}/trigger/{trigger}?key={api_key}'
    time.sleep(1)
    response = requests.put(url, headers={'Content-Type': 'application/json'})
    print(response.status_code)
    print(response.json())
    if response.json()["success"] == True:
        print("added alerts to " + str(group_id))
        return True
    else:
        return False

# Returns all Network Groups in Shodan in Dict { group_name : group_id, ... }
def get_group_listing(api_key):
    url = f'https://api.shodan.io/shodan/alert/info?key={api_key}'
    time.sleep(1)
    response = requests.get(url) # get list of configured network alert groups
    result_dict = {}
    if response. status_code == 200:
        network_alerts = response.json ()
        for alert in network_alerts:  # Iterate through the list of network alerts/groups
            group_name = alert['name']
            group_id = alert['id']
            result_dict[group_name] = group_id # and create groupName → group ID mapping

    return result_dict



TABLE_NAME = get_secret()['DYNAMODB_TABLE']
dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table(TABLE_NAME)
# Triggered on Update to DynamoDB table
# Input - IPAddress and ResourceName of INSERT'ed records
def lambda_handler(event, context):
    """
    DynamoDB Stream-triggered Lambda on INSERT events.
    Extracts IPAddress and ResourceName into variables for each new record.
    """
    api_key = get_secret()['SHODAN_API_KEY']
    group_listing = get_group_listing(api_key)
    # Check all groups for presence of IP
    onboarding_needed = True
    for record in event.get('Records', []):
        # Process only INSERT events
        if record.get('eventName') != 'INSERT':
            continue

        # Retrieve the new image payload
        new_image = record['dynamodb'].get('NewImage', {})

        # Extract attribute values
        ip_address = new_image.get('IPAddress', {}).get('S')
        resource_name = new_image.get('ResourceName', {}).get('S')

        
        for key, val in group_listing.items():
            check_result = check_group_for_ip(ip_address, val, api_key)
            print(f"IP check result for {key} - {check_result}")
            if check_result == True:
                print(f"IP found; no onboarding needed - {key}")
                onboarding_needed = False
                break

        # Onboard if IP not found in onboarded groups
        # Otherwise skip
        if onboarding_needed == True:
            print(f"IP not found in any Shodan groups; onboarding needed")
            # Create new Shodan group
            new_group_id = create_ip_group(api_key, resource_name, ip_address)
            if new_group_id is not None:
                print(f"New Shodan group created - {new_group_id}")

                # Add alerts to new group
                add_alerts_to_group(api_key, new_group_id)
            else:
                print("Error creating new Shodan group")
        
    if onboarding_needed == True:
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'New IP added'})
        }
    if onboarding_needed == False:
        return {
            'statusCode': 200,
            'body': json.dumps({'message': 'IP already onboarded'})
        }

