"""
rag/training/train_unsloth_qlora.py
==================================
Production QLoRA Fine-Tuning Script using Unsloth.

Base Model: Qwen3-4B-Instruct ("unsloth/Qwen3-4B-unsloth-bnb-4bit")
Alternative: Phi-4-mini-instruct ("unsloth/phi-4-mini")
Target Hardware: Single GPU (Google Colab Free T4 16GB, RTX 3090/4090, or rented card).
VRAM Footprint: ~3.8 GB in 4-bit NF4.
Output:
- LoRA Adapter: rag/training/qwen3_4b_janus_qlora/
- 16-bit Merged Model: rag/training/qwen3_4b_janus_merged/
- Quantized GGUF: rag/training/gguf/janus-qwen3-4b-q4_k_m.gguf (for offline laptop demo)
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

# Hyperparameters pinned per master prompt
MODEL_CATALOG = {
    "4b": {
        "model_name": "unsloth/Qwen3-4B-unsloth-bnb-4bit",
        "alt_name": "unsloth/Qwen2.5-3B-Instruct-bnb-4bit",
        "batch_size": 2,
        "grad_accum": 4,
        "vram_gb": 3.8,
        "gguf_name": "janus-qwen3-4b-q4_k_m.gguf",
    },
    "8b": {
        "model_name": "unsloth/Qwen3-8B-unsloth-bnb-4bit",
        "alt_name": "unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
        "batch_size": 1,
        "grad_accum": 8,
        "vram_gb": 7.4,
        "gguf_name": "janus-qwen3-8b-q4_k_m.gguf",
    },
}

MAX_SEQ_LENGTH = 2048
LORA_RANK = 16
LORA_ALPHA = 32
LORA_DROPOUT = 0.0
LEARNING_RATE = 2e-4
EPOCHS = 3


def train(
    dataset_path: str,
    output_dir: str = "rag/training/janus_qlora_output",
    model_size: str = "4b",
    base_model: Optional[str] = None,
    export_gguf: bool = True,
) -> None:
    cfg = MODEL_CATALOG.get(model_size.lower(), MODEL_CATALOG["4b"])
    target_model = base_model or cfg["model_name"]
    batch_size = cfg["batch_size"]
    grad_accum = cfg["grad_accum"]

    print(f"=== Project Janus: Compliance-RAG Fine-Tuning ({model_size.upper()}) ===")
    print(f"Base Model: {target_model} (Est. VRAM: ~{cfg['vram_gb']} GB)")
    print(f"Dataset: {dataset_path}")
    print(f"Batch Size: {batch_size} (Grad Accum: {grad_accum})")
    print(f"Max Sequence Length: {MAX_SEQ_LENGTH}")

    try:
        from unsloth import FastLanguageModel
        from unsloth.chat_templates import get_chat_template
        from trl import SFTTrainer
        from transformers import TrainingArguments
        from datasets import load_dataset
    except ImportError:
        print("ERROR: Unsloth is required to run this script.")
        print("Install on GPU environment: pip install \"unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git\"")
        return

    # 1. Load 4-bit Base Model
    print("Loading 4-bit pre-quantized base model...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=base_model,
        max_seq_length=MAX_SEQ_LENGTH,
        dtype=None,  # Auto-detect (Float16 / Bfloat16)
        load_in_4bit=True,
    )

    # 2. Configure QLoRA Adapters
    print(f"Attaching LoRA adapters (r={LORA_RANK}, alpha={LORA_ALPHA})...")
    model = FastLanguageModel.get_peft_model(
        model,
        r=LORA_RANK,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj",
        ],
        lora_alpha=LORA_ALPHA,
        lora_dropout=LORA_DROPOUT,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=3407,
    )

    # 3. Apply ChatML Formatting
    tokenizer = get_chat_template(
        tokenizer,
        chat_template="chatml",
    )

    def formatting_prompts_func(examples):
        convos = examples["messages"]
        texts = [
            tokenizer.apply_chat_template(convo, tokenize=False, add_generation_prompt=False)
            for convo in convos
        ]
        return {"text": texts}

    # 4. Load & Format Dataset
    print("Loading and tokenizing instruction dataset...")
    dataset = load_dataset("json", data_files=dataset_path, split="train")
    dataset = dataset.map(formatting_prompts_func, batched=True)

    # 5. Training Arguments
    training_args = TrainingArguments(
        per_device_train_batch_size=BATCH_SIZE,
        gradient_accumulation_steps=GRAD_ACCUMULATION,
        warmup_steps=10,
        num_train_epochs=EPOCHS,
        learning_rate=LEARNING_RATE,
        fp16=not is_bfloat16_supported(),
        bf16=is_bfloat16_supported(),
        logging_steps=10,
        optim="adamw_8bit",
        weight_decay=0.01,
        lr_scheduler_type="cosine",
        seed=3407,
        output_dir=output_dir,
        report_to="none",
    )

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=MAX_SEQ_LENGTH,
        dataset_num_proc=2,
        packing=False,
        args=training_args,
    )

    # 6. Execute Training
    print("Starting QLoRA fine-tuning...")
    trainer_stats = trainer.train()
    print(f"Training complete! Loss: {trainer_stats.training_loss:.4f}")

    # 7. Save LoRA Adapter
    adapter_path = Path(output_dir)
    adapter_path.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(adapter_path))
    tokenizer.save_pretrained(str(adapter_path))
    print(f"Saved LoRA adapter to {adapter_path}")

    # 8. Export GGUF for Offline Laptop Serving
    if export_gguf:
        gguf_dir = Path("rag/training/gguf")
        gguf_dir.mkdir(parents=True, exist_ok=True)
        print("Exporting model to GGUF (q4_k_m) for offline laptop demo serving via llama.cpp/Ollama...")
        model.save_pretrained_gguf(
            str(gguf_dir / "janus-qwen3-4b"),
            tokenizer,
            quantization_method="q4_k_m",
        )
        print(f"Exported GGUF to {gguf_dir / 'janus-qwen3-4b-q4_k_m.gguf'}")


def is_bfloat16_supported() -> bool:
    try:
        import torch
        return torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    except Exception:
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unsloth QLoRA Fine-Tuning for Project Janus")
    parser.add_argument("--dataset", default="rag/data/instruct_dataset.jsonl", help="Path to JSONL dataset")
    parser.add_argument("--output", default="rag/training/janus_qlora_output", help="Output directory")
    parser.add_argument("--model_size", default="4b", choices=["4b", "8b"], help="Model size tier (4b or 8b)")
    parser.add_argument("--model", default=None, help="Custom base model override")
    parser.add_argument("--no-gguf", action="store_true", help="Skip GGUF export")
    args = parser.parse_args()

    train(
        dataset_path=args.dataset,
        output_dir=args.output,
        model_size=args.model_size,
        base_model=args.model,
        export_gguf=not args.no_gguf,
    )
