"""
rag/training/train_dpo.py
========================
Direct Preference Optimization (DPO) Fine-Tuning Script for Project Janus.

Aligns the fine-tuned compliance explainer model against verified standards reasoning,
penalizing hallucinations, omitted PFS, deprecated lifetimes, and ungrounded citations.

Compatible with:
- Unsloth FastLanguageModel + PatchDPOTrainer
- Hugging Face trl.DPOTrainer
- Dual-tier base models: 4B (Qwen3-4B-Instruct) and 8B (Qwen3-8B-Instruct)
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Optional

MODEL_CATALOG = {
    "4b": {
        "model_name": "unsloth/Qwen3-4B-unsloth-bnb-4bit",
        "alt_name": "unsloth/Qwen2.5-3B-Instruct-bnb-4bit",
        "batch_size": 1,
        "grad_accum": 4,
        "vram_gb": 4.2,
        "gguf_name": "janus-qwen3-4b-dpo-q4_k_m.gguf",
    },
    "8b": {
        "model_name": "unsloth/Qwen3-8B-unsloth-bnb-4bit",
        "alt_name": "unsloth/Qwen2.5-7B-Instruct-bnb-4bit",
        "batch_size": 1,
        "grad_accum": 8,
        "vram_gb": 8.5,
        "gguf_name": "janus-qwen3-8b-dpo-q4_k_m.gguf",
    },
}

MAX_SEQ_LENGTH = 2048
MAX_PROMPT_LENGTH = 512
BETA = 0.1
LEARNING_RATE = 5e-5
EPOCHS = 1


def train_dpo(
    dataset_path: str = "rag/data/distill_dpo_dataset.jsonl",
    output_dir: str = "rag/training/janus_dpo_output",
    model_size: str = "4b",
    sft_adapter_path: Optional[str] = None,
    export_gguf: bool = True,
) -> None:
    cfg = MODEL_CATALOG.get(model_size.lower(), MODEL_CATALOG["4b"])
    base_model = cfg["model_name"]
    batch_size = cfg["batch_size"]
    grad_accum = cfg["grad_accum"]

    print("=== Project Janus: Direct Preference Optimization (DPO) ===")
    print(f"Tier: {model_size.upper()} | Base Model: {base_model}")
    print(f"SFT Adapter Override: {sft_adapter_path or 'None (using base checkpoint)'}")
    print(f"DPO Dataset: {dataset_path}")
    print(f"DPO Beta: {BETA} | Learning Rate: {LEARNING_RATE}")

    if not Path(dataset_path).exists():
        print(f"ERROR: Dataset {dataset_path} does not exist.")
        print("Run `python -m rag.data.distill_synthesizer --mode dpo` first.")
        return

    try:
        from unsloth import FastLanguageModel, PatchDPOTrainer
        from datasets import load_dataset
        from trl import DPOConfig, DPOTrainer
        PatchDPOTrainer()
    except ImportError:
        print("INFO: Unsloth not installed in local environment.")
        print("To run DPO training on a GPU instance (e.g. Google Colab T4/A100 or Lambda):")
        print("  pip install \"unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git\" trl datasets transformers")
        print("Training execution skipped in non-GPU environment.")
        return

    # 1. Load Model with LoRA Adapter
    print("Loading base model in 4-bit...")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=sft_adapter_path or base_model,
        max_seq_length=MAX_SEQ_LENGTH,
        load_in_4bit=True,
    )

    # 2. Add LoRA if starting from raw base model
    if not sft_adapter_path:
        model = FastLanguageModel.get_peft_model(
            model,
            r=16,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
            lora_alpha=32,
            lora_dropout=0.0,
            bias="none",
            use_gradient_checkpointing="unsloth",
        )

    # 3. Load DPO Dataset
    print(f"Loading preference pairs from {dataset_path}...")
    raw_dataset = load_dataset("json", data_files=dataset_path, split="train")

    def format_dpo_sample(sample):
        return {
            "prompt": sample["prompt"],
            "chosen": sample["chosen"],
            "rejected": sample["rejected"],
        }

    dataset = raw_dataset.map(format_dpo_sample)

    # 4. Configure DPOTrainer
    dpo_config = DPOConfig(
        output_dir=output_dir,
        beta=BETA,
        learning_rate=LEARNING_RATE,
        per_device_train_batch_size=batch_size,
        gradient_accumulation_steps=grad_accum,
        num_train_epochs=EPOCHS,
        max_length=MAX_SEQ_LENGTH,
        max_prompt_length=MAX_PROMPT_LENGTH,
        fp16=not is_bfloat16_supported(),
        bf16=is_bfloat16_supported(),
        logging_steps=5,
        save_strategy="epoch",
        optim="adamw_8bit",
        seed=42,
    )

    trainer = DPOTrainer(
        model=model,
        ref_model=None,
        args=dpo_config,
        train_dataset=dataset,
        tokenizer=tokenizer,
    )

    # 5. Execute Training
    print("Starting DPO preference alignment...")
    trainer.train()
    print("DPO training complete!")

    # 6. Save Model
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    model.save_pretrained(str(out_dir))
    tokenizer.save_pretrained(str(out_dir))
    print(f"Saved DPO adapter to {out_dir}")

    # 7. GGUF Export
    if export_gguf:
        gguf_dir = Path("rag/training/gguf")
        gguf_dir.mkdir(parents=True, exist_ok=True)
        export_target = str(gguf_dir / cfg["gguf_name"].replace(".gguf", ""))
        print(f"Exporting GGUF to {export_target}...")
        model.save_pretrained_gguf(
            export_target,
            tokenizer,
            quantization_method="q4_k_m",
        )
        print("GGUF export finished successfully!")


def is_bfloat16_supported() -> bool:
    try:
        import torch
        return torch.cuda.is_available() and torch.cuda.is_bf16_supported()
    except Exception:
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Unsloth DPO Fine-Tuning for Project Janus")
    parser.add_argument("--dataset", default="rag/data/distill_dpo_dataset.jsonl", help="Path to DPO JSONL")
    parser.add_argument("--output", default="rag/training/janus_dpo_output", help="Output directory")
    parser.add_argument("--model_size", default="4b", choices=["4b", "8b"], help="Model size tier")
    parser.add_argument("--sft_adapter", default=None, help="Path to existing SFT adapter to align")
    parser.add_argument("--no_gguf", action="store_true", help="Skip GGUF quantization export")
    args = parser.parse_args()

    train_dpo(
        dataset_path=args.dataset,
        output_dir=args.output,
        model_size=args.model_size,
        sft_adapter_path=args.sft_adapter,
        export_gguf=not args.no_gguf,
    )
