# © 2026 Affinity Ops Ltd. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""
cicada-cli — Command-line tool for the Cicada Governance Platform.

Commands:
    cicada scaffold     Generate a Cicada-compliant agent project
    cicada validate     Validate a cicada.yaml policy file
    cicada register     Register an agent with the Core API from cicada.yaml
    cicada test         Spin up a local Shadow Mode gateway for testing
    cicada status       Check agent registration and trust score

Installation:
    pip install cicada-guard
    # The CLI is installed as the 'cicada' entry point

Usage:
    cicada scaffold --framework=langchain --tools=stripe,slack --risk-level=high
    cicada validate ./cicada.yaml
    cicada register ./cicada.yaml
    cicada test
    cicada status billing-reconciliation-agent
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Resolve the SDK root directory
SDK_ROOT = Path(__file__).parent.parent.parent
TEMPLATES_DIR = SDK_ROOT / "templates"
SCHEMA_PATH = SDK_ROOT / "schema" / "cicada-policy-v1.json"


def main():
    parser = argparse.ArgumentParser(
        prog="cicada",
        description="Cicada Governance Platform CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  cicada scaffold --framework=langchain --tools=stripe,slack --risk-level=high
  cicada validate ./cicada.yaml
  cicada register ./cicada.yaml
  cicada test
  cicada status my-agent-name
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ── scaffold ───────────────────────────────────────────────────────────────
    scaffold_parser = subparsers.add_parser(
        "scaffold",
        help="Generate a Cicada-compliant agent project",
    )
    scaffold_parser.add_argument(
        "--framework", "-f",
        choices=["langchain", "crewai", "python", "node", "autogen"],
        default="python",
        help="Agent framework (default: python)",
    )
    scaffold_parser.add_argument(
        "--tools", "-t",
        type=str,
        default="",
        help="Comma-separated list of tools (e.g. stripe,slack,postgres)",
    )
    scaffold_parser.add_argument(
        "--risk-level", "-r",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Agent risk level (default: medium)",
    )
    scaffold_parser.add_argument(
        "--hitl",
        action="store_true",
        default=False,
        help="Enable HITL (human-in-the-loop) approval",
    )
    scaffold_parser.add_argument(
        "--destructive",
        action="store_true",
        default=False,
        help="Agent has destructive capabilities (shell, filesystem, DDL)",
    )
    scaffold_parser.add_argument(
        "--name", "-n",
        type=str,
        default="",
        help="Agent name (default: auto-generated from framework)",
    )
    scaffold_parser.add_argument(
        "--owner", "-o",
        type=str,
        default="developer@example.com",
        help="Agent owner email",
    )
    scaffold_parser.add_argument(
        "--output", "-d",
        type=str,
        default=".",
        help="Output directory (default: current directory)",
    )

    # ── validate ───────────────────────────────────────────────────────────────
    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate a cicada.yaml policy file",
    )
    validate_parser.add_argument(
        "policy_file",
        nargs="?",
        default="cicada.yaml",
        help="Path to cicada.yaml (default: ./cicada.yaml)",
    )

    # ── register ───────────────────────────────────────────────────────────────
    register_parser = subparsers.add_parser(
        "register",
        help="Register an agent with the Core API from cicada.yaml",
    )
    register_parser.add_argument(
        "policy_file",
        nargs="?",
        default="cicada.yaml",
        help="Path to cicada.yaml (default: ./cicada.yaml)",
    )
    register_parser.add_argument(
        "--gateway-url",
        type=str,
        default="",
        help="Gateway URL (default: CICADA_GATEWAY_URL env var or http://localhost:8080)",
    )

    # ── test ───────────────────────────────────────────────────────────────────
    test_parser = subparsers.add_parser(
        "test",
        help="Spin up a local Shadow Mode gateway for testing",
    )
    test_parser.add_argument(
        "--port", "-p",
        type=int,
        default=8080,
        help="Gateway port (default: 8080)",
    )

    # ── status ─────────────────────────────────────────────────────────────────
    status_parser = subparsers.add_parser(
        "status",
        help="Check agent registration and trust score",
    )
    status_parser.add_argument(
        "agent_name",
        help="Agent name to check",
    )

    args = parser.parse_args()

    if args.command == "scaffold":
        cmd_scaffold(args)
    elif args.command == "validate":
        cmd_validate(args)
    elif args.command == "register":
        cmd_register(args)
    elif args.command == "test":
        cmd_test(args)
    elif args.command == "status":
        cmd_status(args)
    else:
        parser.print_help()
        sys.exit(1)


# ── scaffold command ───────────────────────────────────────────────────────────

TOOL_REGISTRY = {
    "stripe": {
        "name": "stripe-api",
        "description": "Stripe payment processing API",
        "url_patterns": ["https://api.stripe.com/v1/*"],
        "methods": ["GET", "POST"],
        "risk_level": "high",
    },
    "slack": {
        "name": "slack-api",
        "description": "Slack messaging API",
        "url_patterns": ["https://slack.com/api/*"],
        "methods": ["GET", "POST"],
        "risk_level": "medium",
    },
    "postgres": {
        "name": "internal-db",
        "description": "Internal PostgreSQL database API",
        "url_patterns": ["https://api.internal.example.com/v1/db/*"],
        "methods": ["GET", "POST", "PUT", "DELETE"],
        "risk_level": "high",
        "destructive": True,
    },
    "github": {
        "name": "github-api",
        "description": "GitHub repository and code management API",
        "url_patterns": ["https://api.github.com/*"],
        "methods": ["GET", "POST", "PUT", "PATCH", "DELETE"],
        "risk_level": "high",
    },
    "sendgrid": {
        "name": "sendgrid-api",
        "description": "SendGrid email delivery API",
        "url_patterns": ["https://api.sendgrid.com/v3/*"],
        "methods": ["GET", "POST"],
        "risk_level": "medium",
    },
    "openai": {
        "name": "openai-api",
        "description": "OpenAI LLM API",
        "url_patterns": ["https://api.openai.com/v1/*"],
        "methods": ["POST"],
        "risk_level": "medium",
    },
    "anthropic": {
        "name": "anthropic-api",
        "description": "Anthropic Claude API",
        "url_patterns": ["https://api.anthropic.com/v1/*"],
        "methods": ["POST"],
        "risk_level": "medium",
    },
    "shell": {
        "name": "shell-executor",
        "description": "System shell command execution",
        "url_patterns": ["https://api.internal.example.com/v1/exec/*"],
        "methods": ["POST"],
        "risk_level": "critical",
        "destructive": True,
    },
}

FRAMEWORK_TEMPLATES = {
    "langchain": "langchain-financial",
    "crewai": "crewai-research",
    "python": "python-devops",
    "node": "node-notifications",
    "autogen": "autogen-orchestrator",
}


def cmd_scaffold(args):
    """Generate a Cicada-compliant agent project."""
    import yaml

    framework = args.framework
    agent_name = args.name or f"{framework}-agent"
    output_dir = Path(args.output)
    tools_list = [t.strip() for t in args.tools.split(",") if t.strip()]

    print(f"🛡️  Cicada Scaffold")
    print(f"   Framework:  {framework}")
    print(f"   Agent:      {agent_name}")
    print(f"   Tools:      {', '.join(tools_list) or 'none'}")
    print(f"   Risk:       {args.risk_level}")
    print(f"   HITL:       {'✅' if args.hitl else '❌'}")
    print(f"   Destructive: {'⚠️  YES' if args.destructive else '❌'}")
    print()

    # Check if existing template matches
    template_key = FRAMEWORK_TEMPLATES.get(framework)
    template_dir = TEMPLATES_DIR / template_key if template_key else None

    if template_dir and template_dir.exists():
        print(f"📂 Copying template from {template_key}...")
        for item in template_dir.iterdir():
            dest = output_dir / item.name
            if item.is_file() and item.name != "cicada.yaml":
                shutil.copy2(item, dest)
                print(f"   ✅ {item.name}")

    # Generate cicada.yaml
    has_destructive = args.destructive or any(
        TOOL_REGISTRY.get(t, {}).get("destructive", False) for t in tools_list
    )

    # Force HITL for destructive agents
    hitl_enabled = args.hitl or has_destructive
    if has_destructive and not args.hitl:
        print("   ⚠️  Destructive capability detected — HITL auto-enabled")

    policy = {
        "apiVersion": "cicada/v1",
        "kind": "AgentPolicy",
        "identity": {
            "name": agent_name,
            "description": f"AI agent built with {framework}, managed by Cicada governance",
            "type": "autonomous" if args.risk_level in ("high", "critical") else "semi-autonomous",
            "role": "processor",
            "owner": args.owner,
            "business_unit": "engineering",
            "data_classification": "confidential" if args.risk_level in ("high", "critical") else "internal",
            "criticality": args.risk_level,
        },
        "tools": [],
        "enforcement": {
            "velocity": {
                "max_reads_per_minute": 60 if args.risk_level in ("high", "critical") else 100,
                "max_writes_per_minute": 10 if args.risk_level in ("high", "critical") else 20,
                "max_deletes_per_minute": 2 if args.risk_level != "critical" else 0,
                "circuit_breaker_threshold": 5 if args.risk_level in ("high", "critical") else 10,
            },
            "hitl": {
                "enabled": hitl_enabled,
                "timeout_seconds": 3600,
                "auto_deny_on_timeout": True,
                "risk_threshold": 0.4 if args.risk_level == "critical" else 0.6,
            },
            "shadow_mode": False,
            "destructive_capability": has_destructive,
        },
        "provenance": {
            "evar_binding": True,
            "content_tagging": True,
            "audit_retention_days": 730 if args.risk_level in ("high", "critical") else 365,
        },
        "compliance": {
            "frameworks": ["SOC2", "GDPR"],
            "regulatory_region": "GLOBAL",
        },
    }

    # Build tool declarations from registry
    for tool_name in tools_list:
        if tool_name in TOOL_REGISTRY:
            tool_def = TOOL_REGISTRY[tool_name].copy()
            policy["tools"].append(tool_def)
        else:
            # Unknown tool — create a placeholder
            policy["tools"].append({
                "name": tool_name,
                "description": f"Custom tool: {tool_name}",
                "url_patterns": [f"https://api.example.com/v1/{tool_name}/*"],
                "methods": ["GET", "POST"],
                "risk_level": "medium",
            })

    # Write cicada.yaml
    policy_path = output_dir / "cicada.yaml"
    with open(policy_path, "w") as f:
        f.write("# cicada.yaml — Cicada Agent Governance Policy\n")
        f.write(f"# Generated by: cicada scaffold --framework={framework}\n")
        f.write(f"# Agent: {agent_name}\n\n")
        yaml.dump(policy, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    print(f"   ✅ cicada.yaml")

    # Generate .env.template
    env_path = output_dir / ".env.template"
    if not env_path.exists():
        with open(env_path, "w") as f:
            f.write("# Cicada Gateway\n")
            f.write("CICADA_GATEWAY_URL=http://localhost:8080\n")
            f.write("CICADA_SESSION_TOKEN=your-ed25519-session-token-here\n\n")
            f.write("# LLM Provider\n")
            f.write("OPENAI_API_KEY=sk-your-openai-key-here\n")
        print(f"   ✅ .env.template")

    print()
    print(f"✅ Scaffolded {agent_name} in {output_dir.resolve()}")
    print()
    print("Next steps:")
    print(f"  1. Edit cicada.yaml to refine your governance policy")
    print(f"  2. cicada validate ./cicada.yaml")
    print(f"  3. Copy .env.template to .env and fill in credentials")
    print(f"  4. cicada register ./cicada.yaml")
    print(f"  5. Run your agent!")


# ── validate command ───────────────────────────────────────────────────────────

def cmd_validate(args):
    """Validate a cicada.yaml policy file."""
    policy_path = Path(args.policy_file)

    if not policy_path.exists():
        print(f"❌ Policy file not found: {policy_path}")
        sys.exit(1)

    print(f"🔍 Validating {policy_path}...")
    print()

    # Import here to avoid circular dependency at module level
    from cicada_guard.policy import load_policy

    try:
        policy = load_policy(policy_path)
    except Exception as e:
        print(f"❌ Parse error: {e}")
        sys.exit(1)

    # Schema validation passed — run logical validation
    issues = policy.validate()

    print(f"   Agent:       {policy.identity.name}")
    print(f"   Type:        {policy.identity.type}")
    print(f"   Role:        {policy.identity.role}")
    print(f"   Owner:       {policy.identity.owner}")
    print(f"   Tools:       {len(policy.tools)}")
    print(f"   Destructive: {'⚠️  YES' if policy.is_destructive else '❌'}")
    print(f"   HITL:        {'✅' if policy.hitl_enabled else '❌'}")
    print(f"   Shadow Mode: {'🔍' if policy.enforcement.shadow_mode else '❌'}")
    print()

    if issues:
        print(f"⚠️  {len(issues)} issue(s) found:")
        for issue in issues:
            print(f"   ⚠️  {issue}")
        print()
        sys.exit(1)
    else:
        print("✅ Policy is valid — no issues found")

    # Check allowed URLs
    print()
    print("   Allowed URLs:")
    for url in policy.allowed_urls:
        print(f"     • {url}")


# ── register command ───────────────────────────────────────────────────────────

def cmd_register(args):
    """Register an agent with the Core API from cicada.yaml."""
    import requests
    from cicada_guard.policy import load_policy

    policy_path = Path(args.policy_file)
    if not policy_path.exists():
        print(f"❌ Policy file not found: {policy_path}")
        sys.exit(1)

    policy = load_policy(policy_path)
    issues = policy.validate()
    if issues:
        print(f"❌ Policy has {len(issues)} issue(s). Run 'cicada validate' first.")
        sys.exit(1)

    gateway_url = (
        args.gateway_url
        or os.environ.get("CICADA_GATEWAY_URL", "http://localhost:8080")
    )

    print(f"📡 Registering '{policy.identity.name}' with Cicada Gateway...")
    print(f"   Gateway: {gateway_url}")

    # Send registration request
    try:
        registration = {
            "name": policy.identity.name,
            "description": policy.identity.description,
            "type": policy.identity.type,
            "role": policy.identity.role,
            "owner": policy.identity.owner,
            "business_unit": policy.identity.business_unit,
            "data_classification": policy.identity.data_classification,
            "criticality": policy.identity.criticality,
            "tools": [
                {
                    "name": t.name,
                    "url_patterns": t.url_patterns,
                    "methods": t.methods,
                    "destructive": t.destructive,
                }
                for t in policy.tools
            ],
            "hitl_enabled": policy.enforcement.hitl.enabled,
            "hitl_webhook_url": policy.enforcement.hitl.webhook_url,
            "velocity_config": {
                "max_reads_per_minute": policy.enforcement.velocity.max_reads_per_minute,
                "max_writes_per_minute": policy.enforcement.velocity.max_writes_per_minute,
                "max_deletes_per_minute": policy.enforcement.velocity.max_deletes_per_minute,
            },
            "destructive_capability": policy.is_destructive,
            "shadow_mode": policy.enforcement.shadow_mode,
        }

        response = requests.post(
            f"{gateway_url}/v1/agent/register",
            json=registration,
            timeout=10,
        )

        if response.status_code in (200, 201):
            data = response.json()
            print()
            print(f"✅ Agent registered successfully!")
            print(f"   Agent ID:      {data.get('agent_id', 'N/A')}")
            print(f"   Session Token:  {data.get('session_token', 'N/A')[:30]}...")
            print(f"   EVAR:           {data.get('evar', 'N/A')[:40]}...")
            print()
            print("Add this to your .env file:")
            print(f"   CICADA_SESSION_TOKEN={data.get('session_token', 'YOUR_TOKEN')}")
        else:
            print(f"❌ Registration failed: {response.status_code}")
            print(f"   {response.text[:300]}")
            sys.exit(1)

    except requests.ConnectionError:
        print(f"❌ Cannot connect to Gateway at {gateway_url}")
        print("   Is the Sentry Gateway running? Start with: ./start_fleet.sh")
        sys.exit(1)


# ── test command ───────────────────────────────────────────────────────────────

def cmd_test(args):
    """Spin up a local Shadow Mode gateway for testing."""
    port = args.port

    print(f"🧪 Starting local Cicada Gateway in Shadow Mode on port {port}...")
    print()
    print("Shadow Mode means:")
    print("  • All seven enforcement layers are computed and logged")
    print("  • No traffic is actually blocked")
    print("  • You can see what WOULD be blocked in the logs")
    print()

    # Check if Docker is available
    docker_check = shutil.which("docker")
    if not docker_check:
        print("❌ Docker is required for local testing.")
        print("   Install Docker: https://docs.docker.com/get-docker/")
        sys.exit(1)

    # Check for docker-compose.yml in current directory
    compose_file = Path("docker-compose.yml")
    if compose_file.exists():
        print(f"📂 Found docker-compose.yml — starting with docker compose...")
        subprocess.run(
            ["docker", "compose", "up", "-d"],
            check=True,
        )
    else:
        print("No docker-compose.yml found.")
        print("Generate one with: cicada scaffold --framework=langchain")
        print()
        print("Or start the Gateway manually:")
        print(f"  SHADOW_MODE=true ./start_fleet.sh")

    print()
    print(f"Gateway URL: http://localhost:{port}")
    print(f"Dashboard:   http://localhost:3000")
    print()
    print("Test your agent:")
    print(f"  CICADA_GATEWAY_URL=http://localhost:{port} python agent.py")


# ── status command ─────────────────────────────────────────────────────────────

def cmd_status(args):
    """Check agent registration and trust score."""
    import requests

    gateway_url = os.environ.get("CICADA_GATEWAY_URL", "http://localhost:8080")
    agent_name = args.agent_name

    print(f"📡 Checking status for '{agent_name}'...")

    try:
        response = requests.get(
            f"{gateway_url}/v1/agent/{agent_name}/status",
            timeout=10,
        )

        if response.status_code == 200:
            data = response.json()
            print()
            print(f"   Agent:          {data.get('name', agent_name)}")
            print(f"   Status:         {data.get('status', 'unknown')}")
            print(f"   Trust Score:    {data.get('trust_score', 'N/A')}")
            print(f"   Total Actions:  {data.get('total_actions', 0)}")
            print(f"   Blocked:        {data.get('blocked_actions', 0)}")
            print(f"   Last Active:    {data.get('last_active', 'never')}")
        elif response.status_code == 404:
            print(f"❌ Agent '{agent_name}' not found in registry")
        else:
            print(f"❌ Error: {response.status_code} — {response.text[:200]}")

    except requests.ConnectionError:
        print(f"❌ Cannot connect to Gateway at {gateway_url}")
        sys.exit(1)


if __name__ == "__main__":
    main()
