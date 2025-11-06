# src/backend/workflow/vuln_detect/app.py
import os, sys, pathlib, subprocess, tempfile, shutil
import urllib.request, io, zipfile, time
from urllib.parse import urlparse
import boto3

from vuln_scan import extract_sbom, perform_vuln_scan

S3_BUCKET = os.getenv("S3_BUCKET")
OUTPUT_PREFIX = os.getenv("OUTPUT_PREFIX", "verademo")
REPO_ZIP_URL = os.getenv("REPO_ZIP_URL",
    "https://github.com/veracode/verademo/archive/refs/heads/master.zip")

# Grype defaults for Lambda (/tmp is the only writable disk)
os.environ.setdefault("XDG_CACHE_HOME", "/tmp")
os.environ.setdefault("GRYPE_DB_CACHE_DIR", "/tmp/grype/db")
os.environ.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")
os.environ.setdefault("GRYPE_DB_MAX_ALLOWED_BUILT_AGE", "720h")

def _run(cmd, **kw):
    print("RUN:", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.stdout: print("STDOUT:\n", r.stdout)
    if r.stderr: print("STDERR:\n", r.stderr, file=sys.stderr)
    r.check_returncode()
    return r.stdout

def handler(event, context):
    assert S3_BUCKET, "Set S3_BUCKET env var on the function"

    # ---- Optional: /tmp quick check ----
    print("tmp exists?", os.path.isdir("/tmp"), " size(bytes):", shutil.disk_usage("/tmp"))
    print("XDG_CACHE_HOME:", os.getenv("XDG_CACHE_HOME"))
    print("GRYPE_DB_CACHE_DIR:", os.getenv("GRYPE_DB_CACHE_DIR"))
    pathlib.Path("/tmp/grype/db").mkdir(parents=True, exist_ok=True)

    # ---- Grype DB: online update OR offline import from S3 ----
    s3_uri = os.getenv("GRYPE_DB_S3_URI")  # e.g., s3://<bucket>/grype-db/grype-db.tar.zst
    if s3_uri:
        # Offline mode
        print("Using offline DB import:", s3_uri)
        u = urlparse(s3_uri); local = "/tmp/grype-db.tar.zst"
        boto3.client("s3").download_file(u.netloc, u.path.lstrip("/"), local)
        _run(["grype", "db", "import", local, "-vv"])
        os.environ["GRYPE_DB_AUTO_UPDATE"] = "false"
    else:
        # Online DB update (requires internet; remove VPC or add NAT if needed)
        try:
            urllib.request.urlopen("https://grype.anchore.io/databases/v6/latest.json", timeout=10).read(1)
            print("OK: can reach Anchore DB endpoint")
        except Exception as e:
            print("NET PROBE FAILED:", repr(e))
        _run(["grype", "--version"])
        _run(["grype", "db", "update", "-vv"])
        try:
            _run(["grype", "db", "status", "-vv"])
        except subprocess.CalledProcessError as e:
            print(f"WARN: grype db status returned {e.returncode}; continuing")

    # ---- Download VeraDemo, build SBOM, scan ----
    ts = time.strftime("%Y%m%d-%H%M%S")
    work = pathlib.Path("/tmp/work"); work.mkdir(parents=True, exist_ok=True)
    outdir = pathlib.Path("/tmp/out"); outdir.mkdir(parents=True, exist_ok=True)

    with urllib.request.urlopen(REPO_ZIP_URL) as resp:
        zbytes = resp.read()
    with zipfile.ZipFile(io.BytesIO(zbytes)) as zf:
        zf.extractall(work)
    repo_dir = next(p for p in work.iterdir() if p.is_dir())

    sbom_path = str(outdir / "verademo_sbom.cyclonedx.json")
    extract_sbom(str(repo_dir), sbom_path)  # Syft: cyclonedx-json

    scan_json = str(outdir / "verademo_grype_scan.json")
    scan_parq = str(outdir / "verademo_grype_scan.parquet")
    perform_vuln_scan(sbom_path, output_scan_path=scan_json, output_pd_path=scan_parq)

    # ---- Upload to S3 with encryption (KMS if provided) ----
    s3 = boto3.client("s3")
    key_prefix = f"{OUTPUT_PREFIX}/{ts}/"

    extra_args = None
    if os.getenv("S3_ENCRYPT_UPLOADS", "true").lower() == "true":
        kms_id = os.getenv("S3_SSE_KMS_KEY_ID")
        extra_args = {"ServerSideEncryption": "AES256"} if not kms_id \
                     else {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": kms_id}
        # (Alternatively, enable default bucket encryption and omit ExtraArgs.) :contentReference[oaicite:7]{index=7}

    for p in (sbom_path, scan_json, scan_parq):
        key = key_prefix + os.path.basename(p)
        if extra_args:
            s3.upload_file(p, S3_BUCKET, key, ExtraArgs=extra_args)  # :contentReference[oaicite:8]{index=8}
        else:
            s3.upload_file(p, S3_BUCKET, key)

    return {"bucket": S3_BUCKET, "prefix": key_prefix,
            "files": ["verademo_sbom.cyclonedx.json","verademo_grype_scan.json","verademo_grype_scan.parquet"]}
