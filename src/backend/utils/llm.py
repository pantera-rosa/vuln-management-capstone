from __future__ import annotations
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch
import os
import time
import threading
import json
import boto3


def load_llm(model_id: str, with_quantization: bool = False):
    """
    Load an LLM model with automatic GPU/CPU fallback.

    Args:
        model_id: HuggingFace model identifier
        with_quantization: Whether to use quantization (4-bit on GPU, 8-bit dynamic on CPU)

    Returns:
        tuple: (model, tokenizer)
    """
    cuda_available = torch.cuda.is_available()
    use_gpu = os.environ.get("CUDA_VISIBLE_DEVICES") and cuda_available

    if not use_gpu:
        if not os.environ.get("CUDA_VISIBLE_DEVICES"):
            print("🔵 CPU mode forced via CUDA_VISIBLE_DEVICES")
        if not cuda_available:
            print("⚠️  CUDA not available, using CPU")
    else:
        try:
            device_name = torch.cuda.get_device_name(0)
            compute_cap = torch.cuda.get_device_capability(0)
            print(f"🎮 GPU detected: {device_name}")
            print(f"   Compute capability: sm_{compute_cap[0]}{compute_cap[1]}")
        except Exception as e:
            print(f"⚠️  GPU detection failed: {e}")
            print("   Falling back to CPU")
            use_gpu = False

    quantization_config = None
    device_map = None
    torch_dtype = torch.float32  # Default for CPU
    apply_cpu_quantization = False

    if use_gpu:
        device_map = "auto"
        torch_dtype = torch.float16
        if with_quantization:
            print("🔧 Configuring 4-bit quantization for GPU...")
            quantization_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.float16,
                bnb_4bit_use_double_quant=True,
            )
    else:
        device_map = {"": "cpu"}
        if with_quantization:
            print("🔧 Will apply 8-bit quantization for CPU...")
            apply_cpu_quantization = True
            quantization_config = BitsAndBytesConfig(load_in_8bit=True)

    print(f"📥 Loading tokenizer for {model_id}...")
    tokenizer = AutoTokenizer.from_pretrained(model_id)

    print(f"📥 Loading model {model_id}...")
    try:
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            quantization_config=quantization_config,
            device_map=device_map,
            dtype=torch_dtype,
            low_cpu_mem_usage=True,  # more memory efficient
        )

        if apply_cpu_quantization:
            print(f"✅ Model loaded on CPU with 8-bit quantization")
        elif use_gpu and with_quantization:
            print(f"✅ Model loaded on GPU with 4-bit quantization")
        elif use_gpu:
            print(f"✅ Model loaded on GPU")
        else:
            print(f"✅ Model loaded on CPU")

    except RuntimeError as e:
        if "CUDA" in str(e) and use_gpu:
            print(f"❌ GPU loading failed: {e}")
            print("🔄 Attempting to load on CPU instead...")

            # retry on CPU
            if with_quantization:
                quantization_config = BitsAndBytesConfig(load_in_8bit=True)
            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                quantization_config=quantization_config,  # No quantization on CPU
                device_map={"": "cpu"},
                dtype=torch.float32,
                low_cpu_mem_usage=True,
            )

            if with_quantization:
                print(f"✅ Model loaded on CPU (fallback) with 8-bit quantization")
            else:
                print(f"✅ Model loaded on CPU (fallback)")
        else:
            raise

    return model, tokenizer


class ProgressLogger:
    """Thread-based progress logger that shows elapsed time during generation"""

    def __init__(self, start_time):
        self.start_time = start_time
        self.running = True
        self.last_log_time = 0

    def log_progress(self):
        """Print periodic progress updates every 5 seconds"""
        while self.running:
            elapsed = time.time() - self.start_time
            if elapsed - self.last_log_time >= 5:
                print(
                    f"\r   ⏳ Still generating... ({elapsed:.0f}s elapsed)",
                    end="",
                    flush=True,
                )
                self.last_log_time = elapsed
            time.sleep(1)


def invoke_llm_model(model, tokenizer, prompt: str) -> str:
    """
    Generate text using the loaded LLM model.

    Args:
        model: Loaded model
        tokenizer: Loaded tokenizer
        prompt: Input prompt

    Returns:
        str: Generated text
    """
    messages = [
        {
            "role": "system",
            "content": "You are a cybersecurity engineer who is an expert at fixing vulnerable code.",
        },
        {"role": "user", "content": prompt},
    ]

    inputs = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        tokenize=True,
        return_dict=True,
        return_tensors="pt",
    ).to(model.device)

    print(f"🤖 Generating remediation suggestion...")
    print(f"   Prompt length: {len(prompt)} characters")
    print(f"   Input tokens: {inputs['input_ids'].shape[-1]}")

    # reduce max tokens for CPU/local testing (can be overridden via env var)
    max_tokens = int(
        os.environ.get("MAX_NEW_TOKENS", "2048")
    )  # default 2048 for local, 8192 for production
    if max_tokens > 2048:
        print(f"   ⚠️  Large max_new_tokens ({max_tokens}) may be slow on CPU")

    start_time = time.time()

    # start a background thread to log progress every 5 seconds
    progress_logger = ProgressLogger(start_time)
    progress_thread = threading.Thread(target=progress_logger.log_progress, daemon=True)
    progress_thread.start()

    print(f"   ⏳ Starting generation (this may take a while on CPU)...")

    outputs = model.generate(
        **inputs,
        max_new_tokens=max_tokens,
        do_sample=True,  # use sampling for more creative outputs
        temperature=0.7,  # control randomness
        top_p=0.95,  # nucleus sampling
    )

    # progress logging output
    progress_logger.running = False
    progress_thread.join(timeout=1)
    print("\r", end="", flush=True)

    elapsed = time.time() - start_time
    total_tokens = outputs[0].shape[-1] - inputs["input_ids"].shape[-1]

    info = tokenizer.decode(
        outputs[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True
    )

    print(f"Generated {total_tokens} tokens ({len(info)} characters) in {elapsed:.1f}s")
    if elapsed > 0:
        print(f"   📊 Speed: {total_tokens/elapsed:.1f} tokens/sec")
    return info


def invoke_bedrock_model(
    prompt: str,
    model_id: str = "anthropic.claude-3-5-haiku-20241022-v1:0",
    region: str = "us-east-1",
) -> str:
    """
    Generate text using Amazon Bedrock (Claude models).

    Args:
        prompt: Input prompt
        model_id: Bedrock model ID (default: Claude 3.5 Haiku)
        region: AWS region (default: us-east-1)

    Returns:
        str: Generated text
    """
    bedrock = boto3.client("bedrock-runtime", region_name=region)

    messages = [{"role": "user", "content": prompt}]

    request_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 4096,
        "messages": messages,
        "temperature": 0.7,
        "top_p": 0.95,
        "system": "You are a cybersecurity engineer who is an expert at fixing vulnerable code.",
    }

    print(f"🤖 Calling Bedrock API ({model_id})...")
    print(f"   Prompt length: {len(prompt)} characters")

    start_time = time.time()

    try:
        response = bedrock.invoke_model(modelId=model_id, body=json.dumps(request_body))

        response_body = json.loads(response["body"].read())
        elapsed = time.time() - start_time

        generated_text = response_body["content"][0]["text"]

        input_tokens = response_body.get("usage", {}).get("input_tokens", 0)
        output_tokens = response_body.get("usage", {}).get("output_tokens", 0)

        print(
            f"Generated {output_tokens} tokens ({len(generated_text)} characters) in {elapsed:.1f}s"
        )
        print(f"Speed: {output_tokens/elapsed:.1f} tokens/sec")
        print(f"Cost: ~${(input_tokens * 0.8 + output_tokens * 4.0) / 1_000_000:.6f}")

        return generated_text

    except Exception as e:
        print(f"❌ Bedrock API error: {e}")
        raise
