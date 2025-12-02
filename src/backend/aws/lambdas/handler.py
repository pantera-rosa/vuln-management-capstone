import json
import os
import boto3
from datetime import datetime

# Initialize AWS clients
sfn_client = boto3.client('stepfunctions')

# Environment variable for Step Functions ARN
STATE_MACHINE_ARN = os.environ.get('STATE_MACHINE_ARN')

def lambda_handler(event, context):
    """
    Lambda handler for triggering Step Functions workflow.

    Handles CORS and triggers the vulnerability management Step Functions
    with hardcoded parameters.

    Environment Variables:
        STATE_MACHINE_ARN: ARN of the Step Functions state machine to trigger
    """

    # Determine the origin
    origin = event.get('headers', {}).get('origin', '')

    # Allow specific origins
    allowed_origins = [
        'https://vulnguard.pages.dev',
        'http://localhost:5173',  # For local development
        'http://localhost:3000'
    ]

    # Set the origin header
    if origin in allowed_origins:
        cors_origin = origin
    else:
        cors_origin = 'https://vulnguard.pages.dev'  # Default to production

    # CORS headers
    cors_headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': cors_origin,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    }

    # Handle preflight OPTIONS request
    if event.get('requestContext', {}).get('http', {}).get('method') == 'OPTIONS':
        return {
            'statusCode': 200,
            'headers': {
                **cors_headers,
                'Access-Control-Max-Age': '86400'
            },
            'body': ''
        }

    # Handle POST request - trigger Step Functions
    try:
        # Validate that STATE_MACHINE_ARN is configured
        if not STATE_MACHINE_ARN:
            raise ValueError("STATE_MACHINE_ARN environment variable is not set")

        # Create execution name with timestamp
        timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        execution_name = f"workflow-{timestamp}"

        # Hardcoded input for Step Functions
        # You can customize this based on your Step Functions definition
        step_function_input = {
            "repo_url": "https://github.com/apache/logging-log4j1.git",
            "repo_name": "logging-log4j1",
            "timestamp": timestamp
        }

        # Start Step Functions execution
        response = sfn_client.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            name=execution_name,
            input=json.dumps(step_function_input)
        )

        # Get execution ARN
        execution_arn = response['executionArn']

        # Parse ARN to get region and account for console URL
        # ARN format: arn:aws:states:region:account-id:execution:stateMachineName:executionName
        arn_parts = execution_arn.split(':')
        region = arn_parts[3]

        # Construct console URL
        console_url = f"https://console.aws.amazon.com/states/home?region={region}#/executions/details/{execution_arn}"

        print(f"Started Step Functions execution: {execution_arn}")

        return {
            'statusCode': 200,
            'headers': cors_headers,
            'body': json.dumps({
                'success': True,
                'executionArn': execution_arn,
                'executionName': execution_name,
                'consoleUrl': console_url,
                'timestamp': timestamp
            })
        }

    except Exception as e:
        print(f"Error triggering Step Functions: {str(e)}")
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({
                'success': False,
                'error': str(e)
            })
        }
