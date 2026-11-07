#!/usr/bin/env python3
# ABOUTME: Masks sensitive values in a `terraform show -json` plan before the plan job
# ABOUTME: uploads it as an artifact.
"""Mask sensitive values in a `terraform show -json` plan before it is uploaded.

Usage: redact_plan.py <tfplan.raw.json> <tfplan.json>

The uploaded artifact is readable by anyone with repo read access, and
checkov, conftest and infracost never need the secret itself
(standards/08-iac.md 'Private environment file'). Every section that can
carry a value is masked with the sensitivity map Terraform emits next to it:

- resource_changes[].change and resource_drift[].change: before/after by
  before_sensitive/after_sensitive
- planned_values: values by sensitive_values, recursing into child_modules;
  planned_values.outputs by each output's sensitive flag
- output_changes: before/after by the before_sensitive/after_sensitive booleans
- configuration resources[].expressions: constant_value masked where
  planned_values marks the same attribute sensitive for that address
  (instance keys such as [0] or ["x"] stripped, so count/for_each match)
- configuration variables[].default and outputs[].expression: masked where
  the declaration is sensitive or the name is secret-shaped
- configuration module_calls[].expressions: masked where the called module
  declares the variable sensitive or the name is secret-shaped
- configuration.provider_config: constant_value masked for secret-shaped
  attribute names (provider schemas carry no sensitivity map in plan JSON)
- prior_state and variables are dropped outright
"""
import json
import re
import sys

SECRET_NAMES = ("password", "passwd", "secret", "token", "credential", "private_key", "access_key", "api_key")
INSTANCE_KEY = re.compile(r'\[[^\]]*\]')


def secret_shaped(name):
    return any(s in name.lower() for s in SECRET_NAMES)


def config_address(address):
    """Strip instance keys: aws_x.a[0] -> aws_x.a, module.m["k"].aws_x.b -> module.m.aws_x.b."""
    return INSTANCE_KEY.sub("", address or "")


def merge_sensitivity(a, b):
    """Union of two sensitive_values shapes: any instance marking a field sensitive wins."""
    if a is True or b is True:
        return True
    if isinstance(a, dict) and isinstance(b, dict):
        return {k: merge_sensitivity(a.get(k, False), b.get(k, False)) for k in set(a) | set(b)}
    if isinstance(a, list) and isinstance(b, list):
        n = max(len(a), len(b))
        return [merge_sensitivity(a[i] if i < len(a) else False, b[i] if i < len(b) else False) for i in range(n)]
    return a or b


def redact(value, sensitive):
    if sensitive is True:
        return None
    if isinstance(value, dict) and isinstance(sensitive, dict):
        return {k: redact(v, sensitive.get(k, False)) for k, v in value.items()}
    if isinstance(value, list) and isinstance(sensitive, list):
        padded = sensitive + [False] * (len(value) - len(sensitive))
        return [redact(v, s) for v, s in zip(value, padded)]
    return value


def redact_change(change):
    for key in ("before", "after"):
        if change.get(key) is not None:
            change[key] = redact(change[key], change.get(f"{key}_sensitive", False))


def redact_module(module, sensitivity_by_address):
    for res in module.get("resources", []):
        sens = res.get("sensitive_values", {})
        key = config_address(res.get("address"))
        sensitivity_by_address[key] = merge_sensitivity(sensitivity_by_address.get(key, {}), sens)
        if res.get("values") is not None:
            res["values"] = redact(res["values"], sens)
    for child in module.get("child_modules", []):
        redact_module(child, sensitivity_by_address)


def redact_expressions(expressions, sensitive):
    """Mask constant_value in a configuration expressions map using the
    sensitive_values shape planned_values emitted for the same resource."""
    if not isinstance(expressions, dict) or not isinstance(sensitive, dict):
        return
    for name, expr in expressions.items():
        flag = sensitive.get(name, False)
        if isinstance(expr, list):
            # Nested block: a list of expressions maps, flagged by a list.
            flags = flag if isinstance(flag, list) else []
            for i, block in enumerate(expr):
                redact_expressions(block, flags[i] if i < len(flags) else {})
        elif isinstance(expr, dict) and "constant_value" in expr and flag:
            # True, or a non-empty dict/list for an object-typed attribute:
            # null the whole literal rather than pick through it.
            expr["constant_value"] = None


def null_constant(expr):
    if isinstance(expr, dict) and "constant_value" in expr:
        expr["constant_value"] = None


def redact_config_module(module, sensitivity_by_address, prefix=""):
    for res in module.get("resources", []):
        address = prefix + res.get("address", "")
        redact_expressions(res.get("expressions"), sensitivity_by_address.get(address, {}))
    for name, var in module.get("variables", {}).items():
        if "default" in var and (var.get("sensitive") or secret_shaped(name)):
            var["default"] = None
    for name, out in module.get("outputs", {}).items():
        if out.get("sensitive") or secret_shaped(name):
            null_constant(out.get("expression"))
    for name, call in module.get("module_calls", {}).items():
        child = call.get("module", {})
        declared = child.get("variables", {})
        for arg, expr in call.get("expressions", {}).items():
            if declared.get(arg, {}).get("sensitive") or secret_shaped(arg):
                null_constant(expr)
        redact_config_module(child, sensitivity_by_address, f"{prefix}module.{name}.")


def redact_provider_config(provider_config):
    for provider in provider_config.values():
        for name, expr in provider.get("expressions", {}).items():
            if secret_shaped(name):
                null_constant(expr)


def main(raw_path, out_path):
    with open(raw_path, encoding="utf-8") as f:
        plan = json.load(f)

    for section in ("resource_changes", "resource_drift"):
        for rc in plan.get(section, []):
            redact_change(rc.get("change", {}))

    sensitivity_by_address = {}
    if "planned_values" in plan:
        redact_module(plan["planned_values"].get("root_module", {}), sensitivity_by_address)
        for out in plan["planned_values"].get("outputs", {}).values():
            if out.get("sensitive"):
                out["value"] = None

    for change in plan.get("output_changes", {}).values():
        redact_change(change)

    config = plan.get("configuration", {})
    redact_config_module(config.get("root_module", {}), sensitivity_by_address)
    redact_provider_config(config.get("provider_config", {}))

    plan.pop("prior_state", None)
    plan.pop("variables", None)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(plan, f)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
