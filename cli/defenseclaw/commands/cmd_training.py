# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw training - manage GRPO and SFT training runs."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import click

from defenseclaw.context import AppContext, pass_ctx


@click.group()
def training() -> None:
    """Manage local model training (SFT, GRPO).

    \b
    Commands:
      run       Trigger a training run for a category
      status    Show training pipeline status
      list      List trained model versions
      promote   Manually promote a model version
      rollback  Rollback a promoted model
    """


@training.command("run")
@click.argument("category")
@click.option("--backend", type=click.Choice(["grpo-local", "unsloth", "mlx-lm-lora"]), help="Training backend.")
@click.option("--model", "base_model", help="Base model ID or GGUF path.")
@click.option("--algorithm", type=click.Choice(["sft", "grpo", "dpo", "orpo"]), help="Training algorithm.")
@click.option("--group-size", type=int, help="GRPO: number of completions per prompt (G).")
@click.option("--max-gen-length", type=int, help="GRPO: max tokens per completion.")
@click.option("--kl-coef", type=float, help="GRPO: KL penalty coefficient (0=disabled).")
@click.option("--lora-rank", type=int, help="LoRA rank (default 16).")
@click.option("--reward-funcs", multiple=True, help="Reward functions (repeatable). E.g. 'exec:timeout=10'")
@click.option("--memory-mode", type=click.Choice(["auto", "minimal", "standard", "comfort"]), default="auto", help="Memory mode for model placement.")
@click.option("--max-steps", type=int, help="Maximum training steps (0=all prompts).")
@click.option("--dry-run", is_flag=True, help="Show what would be done without running.")
@pass_ctx
def training_run(
    app: AppContext,
    category: str,
    backend: str | None,
    base_model: str | None,
    algorithm: str | None,
    group_size: int | None,
    max_gen_length: int | None,
    kl_coef: float | None,
    lora_rank: int | None,
    reward_funcs: tuple[str, ...],
    memory_mode: str,
    max_steps: int | None,
    dry_run: bool,
) -> None:
    """Trigger a training run for CATEGORY.

    Looks up the category in config.yaml under training.categories[].
    CLI options override config values.

    \b
    Examples:
      defenseclaw training run code_route
      defenseclaw training run code_route --backend grpo-local --algorithm grpo
      defenseclaw training run code_route --reward-funcs "exec:timeout=10" --reward-funcs "format:json"
      defenseclaw training run reasoning --backend grpo-local --group-size 4 --kl-coef 0
    """
    if not app.cfg.training.enabled:
        click.echo("Error: Training is not enabled. Run: defenseclaw setup training --enable", err=True)
        raise SystemExit(1)

    # Find category config
    cat_cfg = None
    for cat in app.cfg.training.categories:
        if cat.name == category:
            cat_cfg = cat
            break

    if cat_cfg is None:
        click.echo(f"Error: Category '{category}' not found in training.categories[]", err=True)
        click.echo("Available categories:", err=True)
        for cat in app.cfg.training.categories:
            click.echo(f"  - {cat.name} (algorithm={cat.algorithm}, base_model={cat.base_model})", err=True)
        raise SystemExit(1)

    # Resolve settings: CLI overrides > category config > defaults
    resolved_backend = backend or app.cfg.training.backend or "grpo-local"
    resolved_algorithm = algorithm or cat_cfg.algorithm or "grpo"
    resolved_model = base_model or cat_cfg.base_model or ""
    resolved_group_size = group_size or getattr(cat_cfg, "group_size", 0) or 4
    resolved_max_gen = max_gen_length or getattr(cat_cfg, "max_gen_length", 0) or 256
    resolved_kl = kl_coef if kl_coef is not None else getattr(cat_cfg, "kl_coef", 0.0)
    resolved_rank = lora_rank or getattr(cat_cfg, "lora_rank", 0) or 16
    resolved_rewards = list(reward_funcs) if reward_funcs else getattr(cat_cfg, "reward_funcs", []) or []
    resolved_max_steps = max_steps or 0

    # Resolve model GGUF path
    models_dir = app.cfg.training.models_dir or os.path.join(app.cfg.data_dir, "models")
    policy_gguf = _resolve_model_path(resolved_model, models_dir)

    click.echo()
    click.echo("  Training Configuration")
    click.echo("  ══════════════════════")
    click.echo(f"    Category:     {category}")
    click.echo(f"    Backend:      {resolved_backend}")
    click.echo(f"    Algorithm:    {resolved_algorithm}")
    click.echo(f"    Base model:   {resolved_model}")
    click.echo(f"    Policy GGUF:  {policy_gguf or '(not found)'}")
    click.echo(f"    Memory mode:  {memory_mode}")
    if resolved_backend == "grpo-local" and resolved_algorithm == "grpo":
        click.echo(f"    Group size:   {resolved_group_size}")
        click.echo(f"    Max gen len:  {resolved_max_gen}")
        click.echo(f"    KL coef:      {resolved_kl}")
        click.echo(f"    LoRA rank:    {resolved_rank}")
        click.echo(f"    Rewards:      {resolved_rewards or '(none — will use default)'}")
    if resolved_max_steps:
        click.echo(f"    Max steps:    {resolved_max_steps}")
    click.echo()

    if dry_run:
        click.echo("  [dry-run] Would start training with above config.")
        return

    if not policy_gguf:
        click.echo(f"Error: Cannot find GGUF model for '{resolved_model}'", err=True)
        click.echo(f"  Looked in: {models_dir}", err=True)
        click.echo(f"  Download with: huggingface-cli download <repo> <file>.gguf --local-dir {models_dir}", err=True)
        raise SystemExit(1)

    # Check dataset availability (traces)
    data_dir = app.cfg.data_dir or os.path.expanduser("~/.defenseclaw")
    db_path = os.path.join(data_dir, "training", "training-store.db")
    if not os.path.exists(db_path):
        click.echo("Error: No training traces found. Traces are captured during normal operation.", err=True)
        click.echo(f"  Expected: {db_path}", err=True)
        raise SystemExit(1)

    # Dispatch to gateway binary (the Go binary handles the actual training)
    click.echo("  Starting training...")
    click.echo(f"  (This may take hours for real models. Progress reported below.)")
    click.echo()

    # Build args for the gateway binary's internal training trigger
    gateway_bin = _find_gateway_binary()
    if not gateway_bin:
        click.echo("Error: defenseclaw-gateway binary not found.", err=True)
        click.echo("  Build it with: make gateway", err=True)
        raise SystemExit(1)

    env = os.environ.copy()
    env["DEFENSECLAW_TRAINING_CATEGORY"] = category
    env["DEFENSECLAW_TRAINING_BACKEND"] = resolved_backend
    env["DEFENSECLAW_TRAINING_ALGORITHM"] = resolved_algorithm
    env["DEFENSECLAW_TRAINING_POLICY_GGUF"] = policy_gguf
    env["DEFENSECLAW_TRAINING_MEMORY_MODE"] = memory_mode
    env["DEFENSECLAW_TRAINING_GROUP_SIZE"] = str(resolved_group_size)
    env["DEFENSECLAW_TRAINING_MAX_GEN_LENGTH"] = str(resolved_max_gen)
    env["DEFENSECLAW_TRAINING_KL_COEF"] = str(resolved_kl)
    env["DEFENSECLAW_TRAINING_LORA_RANK"] = str(resolved_rank)
    env["DEFENSECLAW_TRAINING_MAX_STEPS"] = str(resolved_max_steps)
    if resolved_rewards:
        env["DEFENSECLAW_TRAINING_REWARD_FUNCS"] = json.dumps(resolved_rewards)

    try:
        result = subprocess.run(
            [gateway_bin, "--training-run"],
            env=env,
            check=False,
        )
        if result.returncode == 0:
            click.echo()
            click.echo("  ✓ Training complete!")
        else:
            click.echo(f"  ✗ Training failed (exit code {result.returncode})", err=True)
            raise SystemExit(result.returncode)
    except FileNotFoundError:
        click.echo(f"Error: Cannot execute {gateway_bin}", err=True)
        raise SystemExit(1)


@training.command("status")
@pass_ctx
def training_status(app: AppContext) -> None:
    """Show training pipeline status and recent runs."""
    click.echo()
    click.echo("  Training Pipeline Status")
    click.echo("  ════════════════════════")

    if not app.cfg.training.enabled:
        click.echo("    Status: disabled")
        click.echo()
        click.echo("    Enable with: defenseclaw setup training --enable")
        return

    click.echo("    Status:  enabled")
    click.echo(f"    Backend: {app.cfg.training.backend or 'not configured'}")
    click.echo()

    # Show categories
    if app.cfg.training.categories:
        click.echo("    Categories:")
        for cat in app.cfg.training.categories:
            algo = cat.algorithm or "sft"
            model = cat.base_model or "?"
            click.echo(f"      • {cat.name} ({algo}, {model})")
    else:
        click.echo("    No categories configured.")
    click.echo()

    # Show recent model versions from registry
    models_dir = app.cfg.training.models_dir or os.path.join(app.cfg.data_dir, "models")
    registry_path = os.path.join(models_dir, "registry.json")
    if os.path.exists(registry_path):
        try:
            with open(registry_path) as f:
                registry = json.load(f)
            categories = registry.get("categories", {})
            if categories:
                click.echo("    Trained Models:")
                for cat_name, cat_data in categories.items():
                    promoted = cat_data.get("current_promoted", "none")
                    n_versions = len(cat_data.get("versions", []))
                    click.echo(f"      • {cat_name}: {n_versions} versions, promoted={promoted}")
        except (json.JSONDecodeError, KeyError):
            pass
    click.echo()


@training.command("list")
@click.argument("category", required=False)
@pass_ctx
def training_list(app: AppContext, category: str | None) -> None:
    """List trained model versions, optionally filtered by CATEGORY."""
    models_dir = app.cfg.training.models_dir or os.path.join(app.cfg.data_dir, "models")
    registry_path = os.path.join(models_dir, "registry.json")

    if not os.path.exists(registry_path):
        click.echo("No trained models found. Registry not yet created.")
        return

    with open(registry_path) as f:
        registry = json.load(f)

    categories = registry.get("categories", {})
    if category:
        categories = {k: v for k, v in categories.items() if k == category}

    if not categories:
        click.echo(f"No models found{f' for category {category}' if category else ''}.")
        return

    for cat_name, cat_data in categories.items():
        click.echo(f"\n  {cat_name}:")
        click.echo(f"  {'─' * 40}")
        promoted = cat_data.get("current_promoted", "")
        for version in cat_data.get("versions", []):
            vid = version.get("id", "?")
            ratio = version.get("eval_ratio", 0)
            is_promoted = "★" if vid == promoted else " "
            status = "promoted" if version.get("promoted") else ("rolled back" if version.get("rolled_back") else "registered")
            click.echo(f"    {is_promoted} {vid}  ratio={ratio:.3f}  [{status}]")
    click.echo()


@training.command("promote")
@click.argument("category")
@click.argument("version_id")
@pass_ctx
def training_promote(app: AppContext, category: str, version_id: str) -> None:
    """Manually promote VERSION_ID for CATEGORY."""
    models_dir = app.cfg.training.models_dir or os.path.join(app.cfg.data_dir, "models")
    registry_path = os.path.join(models_dir, "registry.json")

    if not os.path.exists(registry_path):
        click.echo("Error: No registry found.", err=True)
        raise SystemExit(1)

    with open(registry_path) as f:
        registry = json.load(f)

    categories = registry.get("categories", {})
    if category not in categories:
        click.echo(f"Error: Category '{category}' not in registry.", err=True)
        raise SystemExit(1)

    versions = categories[category].get("versions", [])
    found = False
    for v in versions:
        if v.get("id") == version_id:
            v["promoted"] = True
            found = True
        else:
            v["promoted"] = False

    if not found:
        click.echo(f"Error: Version '{version_id}' not found in category '{category}'.", err=True)
        raise SystemExit(1)

    categories[category]["current_promoted"] = version_id

    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=2)

    click.echo(f"  ✓ Promoted {version_id} for category '{category}'")


@training.command("rollback")
@click.argument("category")
@pass_ctx
def training_rollback(app: AppContext, category: str) -> None:
    """Rollback the currently promoted model for CATEGORY."""
    models_dir = app.cfg.training.models_dir or os.path.join(app.cfg.data_dir, "models")
    registry_path = os.path.join(models_dir, "registry.json")

    if not os.path.exists(registry_path):
        click.echo("Error: No registry found.", err=True)
        raise SystemExit(1)

    with open(registry_path) as f:
        registry = json.load(f)

    categories = registry.get("categories", {})
    if category not in categories:
        click.echo(f"Error: Category '{category}' not in registry.", err=True)
        raise SystemExit(1)

    current = categories[category].get("current_promoted", "")
    if not current:
        click.echo(f"No model currently promoted for '{category}'.")
        return

    for v in categories[category].get("versions", []):
        if v.get("id") == current:
            v["promoted"] = False
            v["rolled_back"] = True

    categories[category]["current_promoted"] = ""

    with open(registry_path, "w") as f:
        json.dump(registry, f, indent=2)

    click.echo(f"  ✓ Rolled back '{current}' for category '{category}'")


def _resolve_model_path(model_id: str, models_dir: str) -> str | None:
    """Resolve a model ID to a GGUF file path."""
    # Direct path
    if model_id.endswith(".gguf") and os.path.exists(model_id):
        return model_id

    # Look in models_dir
    if os.path.isdir(models_dir):
        for f in os.listdir(models_dir):
            if f.endswith(".gguf") and model_id.replace("/", "-").lower() in f.lower():
                return os.path.join(models_dir, f)

    # Try as HuggingFace cache path
    hf_cache = os.path.expanduser("~/.cache/huggingface/hub")
    if os.path.isdir(hf_cache):
        for root, dirs, files in os.walk(hf_cache):
            for f in files:
                if f.endswith(".gguf") and "q4_k_m" in f.lower():
                    if model_id.split("/")[-1].lower().replace("-", "") in f.lower().replace("-", ""):
                        return os.path.join(root, f)

    return None


def _find_gateway_binary() -> str | None:
    """Find the defenseclaw-gateway binary."""
    import shutil

    # Check common locations
    candidates = [
        shutil.which("defenseclaw-gateway"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "defenseclaw-gateway"),
        os.path.join(os.getcwd(), "defenseclaw-gateway"),
        os.path.join(os.getcwd(), "bin", "defenseclaw-gateway"),
    ]
    for c in candidates:
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None
