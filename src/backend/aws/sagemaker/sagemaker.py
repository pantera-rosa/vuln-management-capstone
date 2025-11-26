import json
import boto3
from typing import Optional
import os


def invoke_sagemaker_endpoint(
    prompt: str,
    endpoint_name: Optional[str] = None,
    region: Optional[str] = None,
    max_tokens: int = 8192,
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
    if endpoint_name is None:
        endpoint_name = os.environ.get("SAGEMAKER_ENDPOINT_NAME")
        if not endpoint_name:
            raise ValueError(
                "SAGEMAKER_ENDPOINT_NAME environment variable not set."
                "Please set it to your SageMaker endpoint name."
            )

    if region is None:
        region = os.environ.get("SAGEMAKER_REGION", "us-east-1")

    print(f"Invoking SageMaker endpoint: {endpoint_name} in region {region}")

    sagemaker_runtime = boto3.client("sagemaker-runtime", region_name=region)

    payload = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": max_tokens,
            "do_sample": True,
            "temperature": 0.7,
            "top_p": 0.95,
        },
    }

    try:
        response = sagemaker_runtime.invoke_endpoint(
            EndpointName=endpoint_name,
            ContentType="application/json",
            Body=json.dumps(payload),
        )

        result = json.loads(response["Body"].read().decode())

        if isinstance(result, list) and len(result) > 0:
            generated_text = result[0].get("generated_text", "")
        elif isinstance(result, dict):
            generated_text = result.get("generated_text", "")
        else:
            generated_text = str(result)

        cleaned_text = _extract_response_content(generated_text)

        print(f"Generated {len(cleaned_text)} characters from SageMaker endpoint")
        return cleaned_text

    except Exception as e:
        print(f"Error invoking SageMaker endpoint: {e}")
        raise


def _extract_response_content(text: str) -> str:
    """
    Extract only the patched code, removing the prompt if present.
    Prioritizes "Patched code:" marker to get the fixed code.
    """
    patched_markers = ["Patched code:", "PATCHED CODE:", "## Patched code:"]
    for marker in patched_markers:
        if marker in text:
            pos = text.rfind(marker) + len(marker)
            content = text[pos:].strip()
            if content.startswith("```"):
                content = content[3:].strip()
            if content.endswith("```"):
                content = content[:-3].strip()
            return content

    # fallback: return text as is
    return text.strip()
