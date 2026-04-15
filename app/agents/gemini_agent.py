"""Gemini-powered Agentic AI with ReAct loop and tool-use.

This is the TRUE agentic component — Gemini acts as the reasoning brain 
that autonomously decides what to do, uses tools, and takes actions.

Agent capabilities:
  - Analyze vulnerabilities and make prioritization DECISIONS (not hardcoded)
  - Generate remediation scripts for approved patches
  - Simulate patch execution and verify results
  - Reason about blast radius and dependencies using graph tools
  - Communicate between agents via message passing
"""
from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from datetime import datetime

logger = logging.getLogger(__name__)


# ──────────────── Agent Step Tracing ────────────────

@dataclass
class AgentThought:
    """A single step in the agent's ReAct reasoning chain."""
    step_type: str  # "observe", "think", "act", "result"
    content: str
    tool_name: str | None = None
    tool_input: dict | None = None
    tool_output: str | None = None
    timestamp: float = field(default_factory=time.time)
    duration_ms: float = 0

    def to_dict(self) -> dict:
        return {
            "step_type": self.step_type,
            "content": self.content,
            "tool_name": self.tool_name,
            "tool_input": self.tool_input,
            "tool_output": self.tool_output,
            "timestamp": self.timestamp,
            "duration_ms": round(self.duration_ms, 1),
        }


@dataclass
class AgentResult:
    """Complete result of an agent's execution."""
    agent_name: str
    goal: str
    thoughts: list[AgentThought] = field(default_factory=list)
    final_answer: str = ""
    actions_taken: list[dict] = field(default_factory=list)
    total_duration_ms: float = 0

    def to_dict(self) -> dict:
        return {
            "agent_name": self.agent_name,
            "goal": self.goal,
            "thoughts": [t.to_dict() for t in self.thoughts],
            "final_answer": self.final_answer,
            "actions_taken": self.actions_taken,
            "total_duration_ms": round(self.total_duration_ms, 1),
        }


# ──────────────── Tool Definitions ────────────────

def tool_scan_cve_database(cve_id: str) -> str:
    """Look up a CVE in the vulnerability database."""
    from app.loaders import load_vulnerabilities
    vulns = load_vulnerabilities()
    for v in vulns:
        if v.cve_id == cve_id:
            return json.dumps({
                "cve_id": v.cve_id, "cvss": v.cvss, "severity": v.severity,
                "exploit_maturity": v.exploit_maturity, "kev": v.kev,
                "affected_component": v.affected_component,
                "affected_versions": v.affected_versions,
                "patch_version": v.patch_version,
                "description": v.description,
            })
    return f"CVE {cve_id} not found in database"


def tool_check_service_dependencies(service_name: str) -> str:
    """Check what services depend on a given service (blast radius)."""
    from app.loaders import load_services, load_dependencies
    from app.core.graph_engine import DependencyGraph
    services = load_services()
    deps = load_dependencies()
    graph = DependencyGraph(services, deps)
    br = graph.blast_radius(service_name)
    return json.dumps({
        "service": service_name,
        "downstream_count": br.downstream_count,
        "downstream_services": br.downstream_services,
        "critical_path_count": br.critical_path_count,
        "hub_score": br.hub_score,
    })


def tool_get_service_info(service_name: str) -> str:
    """Get detailed info about a service."""
    from app.loaders import load_services
    services = load_services()
    for s in services:
        if s.name == service_name:
            return json.dumps({
                "name": s.name, "tier": s.tier, 
                "internet_facing": s.internet_facing,
                "customer_facing": s.customer_facing,
                "regulatory_scope": s.regulatory_scope,
                "maintenance_window": s.maintenance_window,
                "owner": s.owner,
                "hosting_type": s.hosting_type,
                "components": [{"name": c.name, "version": c.version} for c in s.components],
            })
    return f"Service '{service_name}' not found"


def tool_check_internal_docs(service_name: str) -> str:
    """Check past incidents, runbooks, and change logs for a service."""
    from app.loaders import get_docs_for_service
    docs = get_docs_for_service(service_name)
    if not docs:
        return f"No internal documentation found for {service_name}"
    return json.dumps(docs[:5])


def tool_generate_patch_script(component: str, current_version: str, 
                                target_version: str, service: str) -> str:
    """Generate a remediation script to patch a component."""
    # This is a realistic script generator — in production this would 
    # integrate with actual package managers and CI/CD
    scripts = {
        "spring-boot": f"""#!/bin/bash
# Remediation Script: Upgrade Spring Boot in {service}
# Generated by AI Agent at {datetime.now().isoformat()}
set -euo pipefail

echo "=== Pre-flight checks ==="
kubectl get pods -n {service.lower().replace(' ', '-')} --no-headers | wc -l

echo "=== Creating backup ==="
kubectl create snapshot {service.lower().replace(' ', '-')}-pre-patch-$(date +%Y%m%d)

echo "=== Updating pom.xml ==="
sed -i 's/<spring-boot.version>{current_version}</<spring-boot.version>{target_version}</' pom.xml

echo "=== Running tests ==="
mvn test -Dspring-boot.version={target_version}

echo "=== Building new image ==="
docker build -t {service.lower().replace(' ', '-')}:{target_version} .

echo "=== Rolling deployment ==="
kubectl set image deployment/{service.lower().replace(' ', '-')} \\
  app={service.lower().replace(' ', '-')}:{target_version} \\
  --namespace={service.lower().replace(' ', '-')}

echo "=== Verifying health ==="
kubectl rollout status deployment/{service.lower().replace(' ', '-')} --timeout=300s
curl -sf http://localhost:8080/actuator/health || (echo "HEALTH CHECK FAILED" && exit 1)

echo "=== Patch complete ==="
""",
        "express": f"""#!/bin/bash
# Remediation Script: Upgrade Express in {service}
set -euo pipefail

echo "=== Backing up package-lock.json ==="
cp package-lock.json package-lock.json.bak

echo "=== Upgrading Express ==="
npm install express@{target_version} --save-exact

echo "=== Running security audit ==="
npm audit --production

echo "=== Running tests ==="
npm test

echo "=== Blue-green deployment ==="
pm2 reload {service.lower().replace(' ', '-')} --update-env

echo "=== Post-deploy verification ==="
curl -sf http://localhost:3000/health || pm2 reload {service.lower().replace(' ', '-')} --previous
""",
    }
    
    # Generic script for unknown components
    default_script = f"""#!/bin/bash
# Remediation Script: Upgrade {component} {current_version} → {target_version} in {service}
# Generated by AI Agent at {datetime.now().isoformat()}
set -euo pipefail

echo "Step 1: Pre-flight checks"
echo "Step 2: Create backup/snapshot"
echo "Step 3: Update {component} from {current_version} to {target_version}"
echo "Step 4: Run regression tests"
echo "Step 5: Deploy with rolling update"
echo "Step 6: Health check verification"  
echo "Step 7: Rollback if health check fails"
"""
    
    script = scripts.get(component, default_script)
    return json.dumps({
        "script": script,
        "component": component,
        "from_version": current_version,
        "to_version": target_version,
        "service": service,
        "estimated_duration_minutes": 15,
        "requires_downtime": False,
        "rollback_command": f"kubectl rollout undo deployment/{service.lower().replace(' ', '-')}",
    })


def tool_run_prechecks(service: str, component: str) -> str:
    """Run pre-deployment validation checks. Input: service, component"""
    from app.services.verification_service import run_prechecks
    result = run_prechecks(service, component)
    return json.dumps(result)


def tool_deploy_canary(service: str, component: str, version: str) -> str:
    """Deploy the patch to a canary group (10% traffic). Input: service, component, version"""
    from app.services.execution_service import execute_canary_rollout
    result = execute_canary_rollout(service, component, version)
    return json.dumps(result)


def tool_verify_health(service: str) -> str:
    """Verify the health of a service (latency, error rate, uptime). Input: service"""
    from app.services.verification_service import check_service_health
    result = check_service_health(service)
    return json.dumps(result)


def tool_rollout_full(service: str, component: str, version: str) -> str:
    """Complete the rollout to all production pods. Input: service, component, version"""
    from app.services.execution_service import execute_full_rollout
    result = execute_full_rollout(service, component, version)
    return json.dumps(result)


def tool_panic_rollback(service: str, component: str) -> str:
    """IMMEDIATELY rollback to the previous stable version. Input: service, component"""
    from app.services.rollback_service import rollback_to_previous_version
    result = rollback_to_previous_version(service, component, "previous")
    return json.dumps(result)



# Tool registry
AGENT_TOOLS = {
    "scan_cve_database": {
        "fn": tool_scan_cve_database,
        "description": "Look up a CVE in the vulnerability database. Input: cve_id (string)",
        "parameters": ["cve_id"],
    },
    "check_service_dependencies": {
        "fn": tool_check_service_dependencies,
        "description": "Check blast radius — what services depend on a given service. Input: service_name (string)",
        "parameters": ["service_name"],
    },
    "get_service_info": {
        "fn": tool_get_service_info,
        "description": "Get detailed info about a service (tier, owner, components, regulatory scope). Input: service_name (string)",
        "parameters": ["service_name"],
    },
    "check_internal_docs": {
        "fn": tool_check_internal_docs,
        "description": "Check past incidents, runbooks, and change logs for a service. Input: service_name (string)",
        "parameters": ["service_name"],
    },
    "generate_patch_script": {
        "fn": tool_generate_patch_script,
        "description": "Generate a remediation bash script to patch a component. Input: component, current_version, target_version, service",
        "parameters": ["component", "current_version", "target_version", "service"],
    },
    "run_prechecks": {
        "fn": tool_run_prechecks,
        "description": "Run pre-deployment validation checks (disk, memory, connectivity). Input: service, component",
        "parameters": ["service", "component"],
    },
    "deploy_canary": {
        "fn": tool_deploy_canary,
        "description": "Deploy to canary (10% traffic) to test for regressions. Input: service, component, version",
        "parameters": ["service", "component", "version"],
    },
    "verify_health": {
        "fn": tool_verify_health,
        "description": "Check real-time health metrics (latency, error rate). Input: service",
        "parameters": ["service"],
    },
    "rollout_full": {
        "fn": tool_rollout_full,
        "description": "Scale up to 100% traffic after successful canary. Input: service, component, version",
        "parameters": ["service", "component", "version"],
    },
    "panic_rollback": {
        "fn": tool_panic_rollback,
        "description": "EMERGENCY: Revert to previous stable version if health degrades. Input: service, component",
        "parameters": ["service", "component"],
    },
}


# ──────────────── ReAct Agent Core ────────────────

class GeminiReActAgent:
    """A Gemini-powered agent that uses ReAct (Reason + Act) to solve tasks.
    
    The agent:
    1. Observes the current state
    2. Thinks about what to do (Gemini reasoning)
    3. Decides which tool to use
    4. Executes the tool
    5. Observes the result
    6. Repeats until the task is complete
    """

    def __init__(self, name: str, goal: str, tools: list[str] | None = None, 
                 max_steps: int = 8):
        self.name = name
        self.goal = goal
        self.tools = {k: AGENT_TOOLS[k] for k in (tools or AGENT_TOOLS.keys()) 
                      if k in AGENT_TOOLS}
        self.max_steps = max_steps
        self.result = AgentResult(agent_name=name, goal=goal)
        self._model = None

    def _get_model(self):
        if self._model is None:
            import google.generativeai as genai
            api_key = os.environ.get("GEMINI_API_KEY", "")
            if not api_key:
                raise RuntimeError("GEMINI_API_KEY not set")
            genai.configure(api_key=api_key)
            self._model = genai.GenerativeModel(
                model_name="gemini-2.5-pro",
                generation_config={"temperature": 0.3, "max_output_tokens": 20000},
            )
        return self._model

    def _build_system_prompt(self) -> str:
        tool_descriptions = "\n".join(
            f"  - {name}: {info['description']}"
            for name, info in self.tools.items()
        )
        return f"""You are {self.name}, an autonomous AI agent at Harborview Financial Services.

Your goal: {self.goal}

You have access to these tools:
{tool_descriptions}

You operate in a ReAct loop: Thought → Action → Observation → Thought → ...

For each step, respond in EXACTLY this JSON format:
{{
  "thought": "Your reasoning about what to do next",
  "action": "tool_name",
  "action_input": {{"param1": "value1", "param2": "value2"}}
}}

When you have enough information to complete your goal, respond with:
{{
  "thought": "I now have enough information to provide my final answer",
  "action": "finish",
  "action_input": {{"answer": "Your detailed final answer here"}}
}}

Rules:
- ALWAYS use tools to gather data before making decisions
- NEVER make up data — use tool outputs only
- Reference specific CVEs, scores, and services
- Be decisive and action-oriented
- Return ONLY valid JSON, no other text"""

    async def run(self, context: str = "") -> AgentResult:
        """Execute the ReAct loop."""
        start = time.time()
        model = self._get_model()
        
        system_prompt = self._build_system_prompt()
        conversation = [f"Context: {context}\n\nBegin working on your goal."]
        
        for step in range(self.max_steps):
            # Build prompt with conversation history
            full_prompt = system_prompt + "\n\n" + "\n".join(conversation)
            
            # THINK — ask Gemini what to do
            think_start = time.time()
            try:
                response = model.generate_content(full_prompt)
                response_text = response.text.strip()
                
                # Clean markdown fences
                if response_text.startswith("```"):
                    response_text = response_text.split("\n", 1)[1] if "\n" in response_text else response_text[3:]
                if response_text.endswith("```"):
                    response_text = response_text[:-3]
                response_text = response_text.strip()
                
                parsed = json.loads(response_text)
            except (json.JSONDecodeError, Exception) as e:
                logger.error(f"Agent {self.name} step {step} failed: {e}")
                self.result.thoughts.append(AgentThought(
                    step_type="error", content=f"Failed to parse response: {e}",
                    duration_ms=(time.time() - think_start) * 1000
                ))
                break
            
            thought = parsed.get("thought", "")
            action = parsed.get("action", "finish")
            action_input = parsed.get("action_input", {})
            
            think_duration = (time.time() - think_start) * 1000
            
            # Record the thought
            self.result.thoughts.append(AgentThought(
                step_type="think", content=thought,
                tool_name=action, tool_input=action_input,
                duration_ms=think_duration
            ))
            
            # FINISH — agent decided it's done
            if action == "finish":
                self.result.final_answer = action_input.get("answer", thought)
                break
            
            # ACT — execute the tool
            if action not in self.tools:
                observation = f"Error: Unknown tool '{action}'. Available: {list(self.tools.keys())}"
            else:
                act_start = time.time()
                try:
                    tool_fn = self.tools[action]["fn"]
                    params = self.tools[action]["parameters"]
                    args = [action_input.get(p, "") for p in params]
                    observation = tool_fn(*args)
                except Exception as e:
                    observation = f"Tool error: {e}"
                act_duration = (time.time() - act_start) * 1000
                
                self.result.thoughts.append(AgentThought(
                    step_type="act", content=f"Called {action}",
                    tool_name=action, tool_input=action_input,
                    tool_output=observation[:500],  # Truncate for readability
                    duration_ms=act_duration
                ))
                
                self.result.actions_taken.append({
                    "tool": action, "input": action_input, "step": step
                })
            
            # OBSERVE — add result to conversation
            conversation.append(f"Step {step+1} - Thought: {thought}")
            conversation.append(f"Action: {action}({json.dumps(action_input)})")
            conversation.append(f"Observation: {observation[:800]}")
        
        self.result.total_duration_ms = (time.time() - start) * 1000
        return self.result


# ──────────────── Pre-built Agent Workflows ────────────────

async def run_vulnerability_triage_agent(cve_id: str, service_name: str) -> AgentResult:
    """Run the Vulnerability Triage Agent — autonomously analyzes a CVE and decides priority."""
    agent = GeminiReActAgent(
        name="Vulnerability Triage Agent",
        goal=f"Analyze {cve_id} affecting {service_name}. Determine the true business risk priority by checking the CVE details, the service's tier and dependencies, blast radius, past incidents, and regulatory exposure. Provide a final risk assessment with a priority recommendation.",
        tools=["scan_cve_database", "get_service_info", "check_service_dependencies", "check_internal_docs"],
        max_steps=6,
    )
    return await agent.run(
        context=f"A new vulnerability {cve_id} has been identified in {service_name}. Triage it."
    )


async def run_remediation_agent(cve_id: str, service_name: str, 
                                 component: str, current_version: str,
                                 target_version: str, scenario: str = "success") -> AgentResult:
    """Run the Remediation Agent — autonomously plans and execute patches step-by-step."""
    agent = GeminiReActAgent(
        name="Remediation Agent",
        goal=f"Remediate {cve_id} in {service_name} by upgrading {component} from {current_version} to {target_version}. "
             f"You MUST follow this protocol: 1. Check service info & docs. 2. Run prechecks. 3. Generate script. "
             f"4. Deploy canary and VERIFY health. 5. If healthy, rollout full. If unhealthy, ROLLBACK immediately.",
        tools=["get_service_info", "check_internal_docs", "run_prechecks", "generate_patch_script", 
               "deploy_canary", "verify_health", "rollout_full", "panic_rollback"],
        max_steps=10,
    )
    return await agent.run(
        context=f"Patch {cve_id} approved for {service_name}. Component: {component} {current_version} -> {target_version}. "
                f"SCENARIO: {scenario}. (If scenario is 'failure', you should observe health degradation after canary and then ROLLBACK)."
    )


async def run_blast_radius_agent(service_name: str) -> AgentResult:
    """Run the Blast Radius Agent — analyzes impact if a service goes down."""
    agent = GeminiReActAgent(
        name="Blast Radius Analyst",
        goal=f"Analyze the full blast radius if {service_name} experiences an outage or failed upgrade. Check its dependencies, downstream services, and any past incidents. Provide a clear impact assessment.",
        tools=["get_service_info", "check_service_dependencies", "check_internal_docs"],
        max_steps=5,
    )
    return await agent.run(
        context=f"Management needs a blast radius assessment for {service_name}."
    )
