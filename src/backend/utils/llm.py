from __future__ import annotations
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch
import os
import warnings

def load_llm(model_id: str, with_quantization: bool = False):
    """
    Load an LLM model with automatic GPU/CPU fallback.
    
    Args:
        model_id: HuggingFace model identifier
        with_quantization: Whether to use 4-bit quantization (GPU only)
    
    Returns:
        tuple: (model, tokenizer)
    """
    # Check if CUDA is available and compatible
    cuda_available = torch.cuda.is_available()
    force_cpu = os.environ.get('CUDA_VISIBLE_DEVICES') == ''
    
    if force_cpu:
        print("🔵 CPU mode forced via CUDA_VISIBLE_DEVICES")
        use_gpu = False
    elif not cuda_available:
        print("⚠️  CUDA not available, using CPU")
        use_gpu = False
    else:
        # Check GPU compatibility
        try:
            device_name = torch.cuda.get_device_name(0)
            compute_cap = torch.cuda.get_device_capability(0)
            print(f"🎮 GPU detected: {device_name}")
            print(f"   Compute capability: sm_{compute_cap[0]}{compute_cap[1]}")
            use_gpu = True
        except Exception as e:
            print(f"⚠️  GPU detection failed: {e}")
            print("   Falling back to CPU")
            use_gpu = False
    
    # Prepare loading configuration
    quantization_config = None
    device_map = None
    
    if use_gpu and with_quantization:
        print("⚙️  Loading with 4-bit quantization on GPU...")
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
        )
        device_map = "auto"
    elif use_gpu:
        print("⚙️  Loading model on GPU...")
        device_map = "auto"
    else:
        print("⚙️  Loading model on CPU (this may take longer)...")
        # Force CPU mode
        device_map = {"": "cpu"}
        # Quantization doesn't work well on CPU, disable it
        if with_quantization:
            warnings.warn(
                "Quantization requested but running on CPU. "
                "Quantization will be disabled. For quantization, use GPU mode."
            )
            with_quantization = False
    
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
            torch_dtype=torch.float16 if use_gpu else torch.float32,
            low_cpu_mem_usage=True  # More memory efficient
        )
        
        if use_gpu:
            print(f"✅ Model loaded on GPU")
        else:
            print(f"✅ Model loaded on CPU")
            
    except RuntimeError as e:
        if "CUDA" in str(e) and use_gpu:
            print(f"❌ GPU loading failed: {e}")
            print("🔄 Attempting to load on CPU instead...")
            
            # Retry on CPU
            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                quantization_config=None,  # No quantization on CPU
                device_map={"": "cpu"},
                torch_dtype=torch.float32,
                low_cpu_mem_usage=True
            )
            print(f"✅ Model loaded on CPU (fallback)")
        else:
            raise
    
    return model, tokenizer


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
        {"role": "system", "content": "You are a cybersecurity engineer who is an expert at fixing vulnerable code."},
        {"role": "user", "content": prompt}
    ]

    inputs = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        tokenize=True,
        return_dict=True,
        return_tensors="pt",
    ).to(model.device)

    print(f"🤖 Generating remediation suggestion...")
    outputs = model.generate(
        **inputs,
        max_new_tokens=8192,  # Increased the maximum number of new tokens
        do_sample=True,  # Use sampling for more creative outputs
        temperature=0.7,  # Control randomness
        top_p=0.95,  # Nucleus sampling
    )
    
    info = tokenizer.decode(
        outputs[0][inputs["input_ids"].shape[-1]:],
        skip_special_tokens=True
    )
    
    print(f"✅ Generated {len(info)} characters")
    return info