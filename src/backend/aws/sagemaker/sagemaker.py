import json
import boto3
from typing import Optional
import os

def invoke_sagemaker_endpoint(
    prompt: str,
    endpoint_name: Optional[str] = None,
    region: Optional[str] = None,
    max_tokens: int = 8192
) -> str:
    """
    Invoke a SageMaker endpoint to generate remediation suggestions.
    
    Args:
        prompt: The input prompt for the model
        endpoint_name: SageMaker endpoint name (defaults to SAGEMAKER_ENDPOINT_NAME env var)
        region: AWS region (defaults to SAGEMAKER_REGION env var, then us-east-1)
        max_tokens: Maximum tokens to generate
    
    Returns:
        str: Generated text from the endpoint
    """
    # Get configuration from environment variables or parameters
    if endpoint_name is None:
        endpoint_name = os.environ.get("SAGEMAKER_ENDPOINT_NAME")
        if not endpoint_name:
            raise ValueError(
                "SAGEMAKER_ENDPOINT_NAME environment variable not set. "
                "Please set it to your SageMaker endpoint name."
            )
    
    if region is None:
        region = os.environ.get("SAGEMAKER_REGION", "us-east-1")
    
    print(f"📡 Invoking SageMaker endpoint: {endpoint_name} in region {region}")
    
    # Create SageMaker runtime client
    sagemaker_runtime = boto3.client(
        "sagemaker-runtime",
        region_name=region
    )
    
    # Prepare the payload for Meta text generation models
    payload = {
        "inputs": [prompt],
        "parameters": {
            "max_new_tokens": max_tokens,
            "do_sample": True,
            "temperature": 0.7,
            "top_p": 0.95,
        }
    }
    
    try:
        # Invoke the endpoint
        response = sagemaker_runtime.invoke_endpoint(
            EndpointName=endpoint_name,
            ContentType="application/json",
            Body=json.dumps(payload)
        )
        
        # Parse the response
        result = json.loads(response["Body"].read().decode())
        
        # Extract generated text from response
        # Meta models typically return: [{"generated_text": "..."}]
        if isinstance(result, list) and len(result) > 0:
            generated_text = result[0].get("generated_text", "")
        elif isinstance(result, dict):
            generated_text = result.get("generated_text", "")
        else:
            generated_text = str(result)
        
        print(f"✅ Generated {len(generated_text)} characters from SageMaker endpoint")
        return generated_text
        
    except Exception as e:
        print(f"❌ Error invoking SageMaker endpoint: {e}")
        raise

