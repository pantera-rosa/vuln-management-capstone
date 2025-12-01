from __future__ import annotations
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch
import os
import time
import threading


def load_llm(model_id: str, with_quantization: bool = False):
    """
    Load an LLM model with automatic GPU/CPU fallback.

    Args:
        model_id: HuggingFace model identifier
        with_quantization: Whether to use quantization (4-bit on GPU, 8-bit dynamic on CPU)

    Returns:
        tuple: (model, tokenizer)
    """
    # Check if CUDA is available and compatible
    cuda_available = torch.cuda.is_available()
    use_gpu = os.environ.get("CUDA_VISIBLE_DEVICES") and cuda_available

    if not use_gpu:
        if not os.environ.get("CUDA_VISIBLE_DEVICES"):
            print("🔵 CPU mode forced via CUDA_VISIBLE_DEVICES")
        if not cuda_available:
            print("⚠️  CUDA not available, using CPU")
    else:
        # Check GPU compatibility
        try:
            device_name = torch.cuda.get_device_name(0)
            compute_cap = torch.cuda.get_device_capability(0)
            print(f"🎮 GPU detected: {device_name}")
            print(f"   Compute capability: sm_{compute_cap[0]}{compute_cap[1]}")
        except Exception as e:
            print(f"⚠️  GPU detection failed: {e}")
            print("   Falling back to CPU")
            use_gpu = False

    # Prepare loading configuration
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

    # Load tokenizer
    print(f"📥 Loading tokenizer for {model_id}...")
    tokenizer = AutoTokenizer.from_pretrained(model_id)

    # Load model with error handling
    print(f"📥 Loading model {model_id}...")
    try:
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            quantization_config=quantization_config,
            device_map=device_map,
            dtype=torch_dtype,
            low_cpu_mem_usage=True,  # More memory efficient
        )

        # Debug print statements
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

            # Retry on CPU
            if with_quantization:
                quantization_config = BitsAndBytesConfig(load_in_8bit=True)
            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                quantization_config=quantization_config,  # No quantization on CPU
                device_map={"": "cpu"},
                dtype=torch.float32,
                low_cpu_mem_usage=True,
            )

            # Debug print statements
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
            # Log every 5 seconds
            if elapsed - self.last_log_time >= 5:
                print(
                    f"\r   ⏳ Still generating... ({elapsed:.0f}s elapsed)",
                    end="",
                    flush=True,
                )
                self.last_log_time = elapsed
            time.sleep(1)  # Check every second


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

    # Reduce max tokens for CPU/local testing (can be overridden via env var)
    max_tokens = int(
        os.environ.get("MAX_NEW_TOKENS", "2048")
    )  # Default 2048 for local, 8192 for production
    if max_tokens > 2048:
        print(f"   ⚠️  Large max_new_tokens ({max_tokens}) may be slow on CPU")

    start_time = time.time()

    # Start a background thread to log progress every 5 seconds
    progress_logger = ProgressLogger(start_time)
    progress_thread = threading.Thread(target=progress_logger.log_progress, daemon=True)
    progress_thread.start()

    print(f"   ⏳ Starting generation (this may take a while on CPU)...")

    # Generate (this is the blocking call that takes time)
    outputs = model.generate(
        **inputs,
        max_new_tokens=max_tokens,
        do_sample=True,  # Use sampling for more creative outputs
        temperature=0.7,  # Control randomness
        top_p=0.95,  # Nucleus sampling
    )

    # Stop progress logging thread
    progress_logger.running = False
    progress_thread.join(timeout=1)  # Wait for thread to finish

    # Clear the progress line
    print("\r", end="", flush=True)

    elapsed = time.time() - start_time
    total_tokens = outputs[0].shape[-1] - inputs["input_ids"].shape[-1]

    info = tokenizer.decode(
        outputs[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=True
    )

    print(
        f"   ✅ Generated {total_tokens} tokens ({len(info)} characters) in {elapsed:.1f}s"
    )
    if elapsed > 0:
        print(f"   📊 Speed: {total_tokens/elapsed:.1f} tokens/sec")
    return info
