from __future__ import annotations
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig
import torch

def load_llm(model_id: str, with_quantization : bool = False):
    quantization_config = None
    if with_quantization:
        quantization_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_use_double_quant=True,
        )
    
    tokenizer = AutoTokenizer.from_pretrained(model_id)
    model = AutoModelForCausalLM.from_pretrained(model_id, quantization_config=quantization_config, device_map="auto")
    return model, tokenizer

def invoke_llm_model(model, tokenizer, prompt: str) -> str:
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

    outputs = model.generate(
        **inputs,
        max_new_tokens=8192 # Increased the maximum number of new tokens
        )
    info = tokenizer.decode(outputs[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)
    return info