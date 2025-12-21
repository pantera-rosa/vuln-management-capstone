import json
import os
import boto3
from datetime import datetime, timedelta
from urllib.parse import urlparse

# Initialize AWS clients
sfn_client = boto3.client('stepfunctions')
s3_client = boto3.client('s3')

# Environment variables
STATE_MACHINE_ARN = os.environ.get('STATE_MACHINE_ARN')
S3_BUCKET = os.environ.get('S3_BUCKET')
CACHE_EXPIRY_HOURS = int(os.environ.get('CACHE_EXPIRY_HOURS', '168'))  # Default: 7 days

def lambda_handler(event, context):
    """
    Lambda handler for triggering Step Functions workflow with intelligent caching.

    Checks if remediation results already exist in S3 before triggering pipeline.
    If recent results exist, returns cached data instead of re-running pipeline.

    Environment Variables:
        STATE_MACHINE_ARN: ARN of the Step Functions state machine to trigger
        S3_BUCKET: S3 bucket name for results
        CACHE_EXPIRY_HOURS: Hours before cache expires (default: 168 = 7 days)
    
    Query Parameters:
        force_rescan: Set to 'true' to bypass cache and force new scan
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

    # Handle POST request - trigger Step Functions (with cache check)
    try:
        # Validate environment variables
        if not STATE_MACHINE_ARN:
            raise ValueError("STATE_MACHINE_ARN environment variable is not set")
        if not S3_BUCKET:
            raise ValueError("S3_BUCKET environment variable is not set")

        # Get repo_url from request body
        # The website should send JSON like: {"repo_url": "https://github.com/user/repo"}
        body = event.get('body', '{}')
        
        # Handle both string and already-parsed body
        if isinstance(body, str):
            try:
                body_data = json.loads(body) if body else {}
            except json.JSONDecodeError:
                return {
                    'statusCode': 400,
                    'headers': cors_headers,
                    'body': json.dumps({
                        'success': False,
                        'error': 'Invalid JSON in request body'
                    })
                }
        else:
            body_data = body
        
        # Get repo_url from body, or check query parameters as fallback
        repo_url = body_data.get('repo_url')
        
        if not repo_url:
            # Try query parameters as fallback
            query_params = event.get('queryStringParameters', {}) or {}
            repo_url = query_params.get('repo_url')
        
        # Validate that repo_url was provided
        if not repo_url:
            return {
                'statusCode': 400,
                'headers': cors_headers,
                'body': json.dumps({
                    'success': False,
                    'error': 'Missing required parameter: repo_url',
                    'message': 'Please provide a GitHub repository URL',
                    'example': {
                        'repo_url': 'https://github.com/apache/struts'
                    }
                })
            }
        
        # Validate repo_url format
        if not repo_url.startswith('https://github.com/'):
            return {
                'statusCode': 400,
                'headers': cors_headers,
                'body': json.dumps({
                    'success': False,
                    'error': 'Invalid repository URL',
                    'message': 'Only GitHub repositories are supported. URL must start with https://github.com/',
                    'provided': repo_url,
                    'example': 'https://github.com/apache/struts'
                })
            }
        
        # Extract repo name from URL
        repo_name = extract_repo_name(repo_url)
        
        if not repo_name:
            return {
                'statusCode': 400,
                'headers': cors_headers,
                'body': json.dumps({
                    'success': False,
                    'error': 'Could not extract repository name from URL',
                    'provided': repo_url
                })
            }
        
        print(f"Processing scan request for repository: {repo_name}")
        print(f"Full URL: {repo_url}")
        
        # Check for force_rescan query parameter
        query_params = event.get('queryStringParameters', {}) or {}
        force_rescan = query_params.get('force_rescan', '').lower() == 'true'
        
        # Check if cached results exist (unless force_rescan is true)
        if not force_rescan:
            cached_result = check_cached_results(S3_BUCKET, repo_name)
            
            if cached_result:
                print(f"Found cached results for {repo_name}: {cached_result['scan_id']}")
                print(f"Cache age: {cached_result['age_hours']:.1f} hours")

                # Read the contents of the S3 files corresponding to cached_result['remediations'] into a string.
                # First check if there is a "json" field with a non empty S3 path. If so, read the S3 file.
                # If there is no "json" field, check if there is a "csv" field and do the same.
                # Ff neither exist, set the string value to None.
                remediations_output = None
                if 'json' in cached_result['remediations']:
                    remediations_output = read_s3_file(cached_result['remediations']['json'])
                elif 'csv' in cached_result['remediations']:
                    remediations_output = read_s3_file(cached_result['remediations']['csv'])
                
                return {
                    'statusCode': 200,
                    'headers': cors_headers,
                    'body': json.dumps({
                        'success': True,
                        'cached': True,
                        'message': 'Returning cached results from recent scan',
                        'scan_id': cached_result['scan_id'],
                        'cache_age_hours': round(cached_result['age_hours'], 1),
                        'cache_age_days': round(cached_result['age_hours'] / 24, 1),
                        'scan_timestamp': cached_result['timestamp'],
                        'paths': {
                            'remediations': cached_result['remediations'],
                            'assessments': cached_result.get('assessments'),
                            's3_structure': cached_result.get('s3_structure', {
                                'assessments': f"s3://{S3_BUCKET}/assessments/{cached_result['scan_id']}/",
                                'identifications': f"s3://{S3_BUCKET}/identifications/{cached_result['scan_id']}/",
                                'scans': f"s3://{S3_BUCKET}/scans/{cached_result['scan_id']}/",
                                'remediations': f"s3://{S3_BUCKET}/remediations/"
                            })
                        },
                        'remediations_output': remediations_output
                    })
                }
        
        # No valid cache or force_rescan - trigger new pipeline
        print(f"{'Force rescan requested' if force_rescan else 'No valid cache found'} - triggering new pipeline for {repo_name}")
        
        # Create execution name with timestamp and repo name
        timestamp = datetime.utcnow().strftime('%Y%m%d-%H%M%S')
        # Sanitize repo name for execution name (remove special chars)
        safe_repo_name = repo_name.replace('/', '-').replace('.', '-')
        execution_name = f"scan-{safe_repo_name}-{timestamp}"

        # Step Functions input
        step_function_input = {
            "repo_url": repo_url,
            "s3_bucket": S3_BUCKET
        }

        # Start Step Functions execution
        response = sfn_client.start_execution(
            stateMachineArn=STATE_MACHINE_ARN,
            name=execution_name,
            input=json.dumps(step_function_input)
        )

        # Get execution ARN
        execution_arn = response['executionArn']

        # Parse ARN to get region for console URL
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
                'cached': False,
                'message': 'Started new vulnerability scan pipeline',
                'executionArn': execution_arn,
                'executionName': execution_name,
                'consoleUrl': console_url,
                'timestamp': timestamp,
                'estimated_completion_minutes': 15
            })
        }

    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'headers': cors_headers,
            'body': json.dumps({
                'success': False,
                'error': str(e),
                'error_type': type(e).__name__
            })
        }

def read_s3_file(s3_path):
    """
    Read the contents of an S3 file into a string.
    """
    if not s3_path or not s3_path.strip():
        return None

    bucket, key = s3_path.replace("s3://", "").split("/", 1)
    obj = s3_client.get_object(Bucket=bucket, Key=key)
    return obj['Body'].read().decode('utf-8')

def extract_repo_name(repo_url):
    """
    Extract repository name from GitHub URL.
    
    Examples:
        https://github.com/Vuln-Guard/logging-log4j1 -> logging-log4j1
        https://github.com/apache/struts.git -> struts
    """
    parsed = urlparse(repo_url)
    path = parsed.path.strip('/')
    
    # Get last part of path (repo name)
    repo_name = path.split('/')[-1]
    
    # Remove .git extension if present
    if repo_name.endswith('.git'):
        repo_name = repo_name[:-4]
    
    return repo_name


def check_cached_results(bucket, repo_name):
    """
    Check if valid cached remediation results exist for the given repository.
    
    Based on actual S3 structure:
    - assessments/{scan_id}/ - Has scan_id subfolders
    - remediations/ - Files directly in root (NO subfolders)
    
    Strategy:
    1. Check assessments/ for scan_id folders matching repo
    2. Extract timestamp from scan_id
    3. Find matching remediation files by timestamp
    
    Args:
        bucket: S3 bucket name
        repo_name: Repository name (e.g., 'logging-log4j1')
    
    Returns:
        dict with cached result info if found and valid, None otherwise
    """
    try:
        # Step 1: List assessment folders to find scans for this repo
        assessment_prefix = "assessments/"
        
        response = s3_client.list_objects_v2(
            Bucket=bucket,
            Prefix=assessment_prefix,
            Delimiter='/'
        )
        
        if 'CommonPrefixes' not in response:
            print(f"No assessments found in s3://{bucket}/{assessment_prefix}")
            return None
        
        # Find assessment folders matching this repo
        matching_scans = []
        for prefix_obj in response['CommonPrefixes']:
            folder = prefix_obj['Prefix']
            scan_id = folder.rstrip('/').split('/')[-1]
            
            # Check if scan_id starts with repo_name
            # Format: logging-log4j1-20251208-224448
            if scan_id.startswith(f"{repo_name}-"):
                matching_scans.append(scan_id)
        
        if not matching_scans:
            print(f"No cached results found for repo: {repo_name}")
            return None
        
        # Get the most recent scan for this repo
        # Sort by scan_id (which includes timestamp)
        matching_scans.sort(reverse=True)
        latest_scan_id = matching_scans[0]
        
        print(f"Found {len(matching_scans)} cached scan(s) for {repo_name}, latest: {latest_scan_id}")
        
        # Step 2: Extract timestamp from scan_id
        # Format: logging-log4j1-20251208-224448
        # We need to extract: 20251208-224448
        parts = latest_scan_id.split('-')
        if len(parts) >= 3:
            # Last two parts are date and time
            date_part = parts[-2]  # 20251208
            time_part = parts[-1]  # 224448
            timestamp_str = f"{date_part}-{time_part}"
            
            try:
                scan_datetime = datetime.strptime(timestamp_str, "%Y%m%d-%H%M%S")
            except ValueError:
                print(f"Could not parse timestamp from scan_id: {latest_scan_id}")
                return None
        else:
            print(f"Invalid scan_id format: {latest_scan_id}")
            return None
        
        # Step 3: Calculate age and check validity
        age = datetime.utcnow() - scan_datetime
        age_hours = age.total_seconds() / 3600
        
        if age_hours > CACHE_EXPIRY_HOURS:
            print(f"Cache expired: {age_hours:.1f} hours old (limit: {CACHE_EXPIRY_HOURS} hours)")
            return None
        
        # Step 4: Check if assessment files exist
        assessment_folder_prefix = f"assessments/{latest_scan_id}/"
        assessment_objects = s3_client.list_objects_v2(
            Bucket=bucket,
            Prefix=assessment_folder_prefix,
            MaxKeys=10
        )
        
        if 'Contents' not in assessment_objects:
            print(f"Assessment folder is empty: {assessment_folder_prefix}")
            return None
        
        assessment_files = {}
        for obj in assessment_objects['Contents']:
            key = obj['Key']
            filename = key.split('/')[-1]
            if filename.startswith('assessment_') and filename.endswith('.csv'):
                assessment_files['csv'] = f"s3://{bucket}/{key}"
            elif filename.startswith('assessment_') and filename.endswith('.parquet'):
                assessment_files['parquet'] = f"s3://{bucket}/{key}"
        
        if not assessment_files:
            print(f"No assessment files found in {assessment_folder_prefix}")
            return None
        
        # Step 5: Look for remediation files in remediations/ root
        # Remediation filename pattern: remediation_assessment_20251208-225344.csv
        # We need to find files with similar timestamp to our scan
        
        remediation_prefix = "remediations/"
        remediation_objects = s3_client.list_objects_v2(
            Bucket=bucket,
            Prefix=remediation_prefix,
            MaxKeys=100  # Get recent files
        )
        
        remediation_files = {}
        if 'Contents' in remediation_objects:
            # Look for remediation files with matching or close timestamp
            # Remediation timestamp might be slightly later than assessment timestamp
            # We'll look for files within 1 hour of the assessment
            
            for obj in remediation_objects['Contents']:
                key = obj['Key']
                filename = key.split('/')[-1]
                
                # Parse remediation filename: remediation_assessment_20251208-225344.csv
                if filename.startswith('remediation_assessment_'):
                    try:
                        # Extract timestamp from filename
                        # Format: remediation_assessment_20251208-225344.csv
                        timestamp_part = filename.replace('remediation_assessment_', '').replace('.csv', '').replace('.parquet', '')
                        remediation_datetime = datetime.strptime(timestamp_part, "%Y%m%d-%H%M%S")
                        
                        # Check if this remediation is within 2 hours of the assessment
                        time_diff = abs((remediation_datetime - scan_datetime).total_seconds() / 3600)
                        
                        if time_diff <= 2:  # Within 2 hours
                            if filename.endswith('.csv'):
                                remediation_files['csv'] = f"s3://{bucket}/{key}"
                            elif filename.endswith('.parquet'):
                                remediation_files['parquet'] = f"s3://{bucket}/{key}"
                    except ValueError:
                        continue
        
        if not remediation_files:
            print(f"No remediation files found for scan {latest_scan_id}")
            print(f"Looked in s3://{bucket}/remediations/ for files near timestamp {timestamp_str}")
            return None
        
        print(f"Found remediation files: {list(remediation_files.keys())}")
        
        # Return cached result info
        return {
            'scan_id': latest_scan_id,
            'timestamp': scan_datetime.isoformat(),
            'age_hours': age_hours,
            'remediations': remediation_files,
            'assessments': assessment_files,
            's3_structure': {
                'assessments_folder': f"s3://{bucket}/assessments/{latest_scan_id}/",
                'identifications_folder': f"s3://{bucket}/identifications/{latest_scan_id}/",
                'scans_folder': f"s3://{bucket}/scans/{latest_scan_id}/",
                'remediations_root': f"s3://{bucket}/remediations/"
            }
        }
        
    except Exception as e:
        print(f"Error checking cached results: {e}")
        import traceback
        traceback.print_exc()
        return None