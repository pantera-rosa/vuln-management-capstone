import os
from pathlib import Path

import boto3
import pandas as pd

from src.backend.workflow.vuln_remediate.generate_remediation import (
    generate_remediation,
)


def main() -> None:
    bucket = os.environ["S3_BUCKET"]
    assessments_prefix = os.environ.get("S3_ASSESSMENTS_PREFIX", "assessments")
    remediation_prefix = os.environ.get("S3_REMEDIATION_PREFIX", "remediations")
    model_id = os.environ.get("MODEL_ID", "meta-llama/Meta-Llama-3.1-8B-Instruct")
    use_4bit = os.environ.get("USE_4BIT_QUANTIZATION", "false").lower() == "true"

    s3 = boto3.client("s3")

    # Find the most recent assessment object under the prefix
    prefix = assessments_prefix.rstrip("/") + "/"
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    contents = resp.get("Contents", [])
    if not contents:
        raise RuntimeError(f"No assessment objects found under s3://{bucket}/{prefix}")

    latest_obj = max(contents, key=lambda o: o["LastModified"])
    latest_assessment = latest_obj["Key"]

    print(f"Bucket={bucket}, latest_assessment={latest_assessment}")

    local_path = "/tmp/assessment.parquet"
    s3.download_file(bucket, latest_assessment, local_path)

    df = pd.read_parquet(local_path)
    print(f"Loaded {len(df)} vulnerability records")

    output_parquet = "/tmp/remediation_results.parquet"
    output_json = "/tmp/remediation_results.json"

    remediated_df = generate_remediation(
        vuln_df=df,
        model_id=model_id,
        output_pd_path=output_parquet,
        dep_repos_root_dir_path="./artifacts/identify/repos",
        with_quantization=use_4bit,
        use_sagemaker=False,
        sagemaker_endpoint_name=None,
        aws_region=os.environ.get("AWS_DEFAULT_REGION", "us-east-1"),
    )

    print(f"✅ Remediation complete. Generated {len(remediated_df)} fixes")

    assessment_stem = Path(latest_assessment).stem
    parquet_key = f"{remediation_prefix}/remediation_{assessment_stem}.parquet"
    json_key = f"{remediation_prefix}/remediation_{assessment_stem}.json"

    s3.upload_file(output_parquet, bucket, parquet_key)
    s3.upload_file(output_json, bucket, json_key)

    print(f"✅ Uploaded: s3://{bucket}/{parquet_key}")
    print(f"✅ Uploaded: s3://{bucket}/{json_key}")


if __name__ == "__main__":
    main()
