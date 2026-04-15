from app.agents.orchestrator import Orchestrator
from app.loaders import load_services, load_dependencies, load_vulnerabilities, load_approvals
from app.services.execution_state import get_all_executions

def debug_plan():
    services = load_services()
    deps = load_dependencies()
    vulns = load_vulnerabilities()
    orch = Orchestrator(services, deps, vulns)
    result = orch.run()
    
    print(f"Total plan items: {len(result.plan)}")
    for i in range(min(15, len(result.plan))):
        p = result.plan[i]
        print(f"Rank {p.priority_rank}: {p.cve_id} in {p.service}")

    _resolved_items = set() # simulating empty state
    
    executions = get_all_executions()
    completed_keys = { (ex['cve_id'], ex['service']) for ex in executions if ex['status'] == 'completed' }
    print(f"Completed keys: {completed_keys}")

    approvals = load_approvals()
    rejected_keys = { (a.get('cve_id'), a.get('service')) for a in approvals if a.get('decision') == 'rejected' }
    print(f"Rejected keys: {rejected_keys}")

    active_plan = [
        p for p in result.plan
        if (p.cve_id, p.service) not in _resolved_items 
        and (p.cve_id, p.service) not in completed_keys
        and (p.cve_id, p.service) not in rejected_keys
    ]
    
    print(f"Active plan items: {len(active_plan)}")
    if active_plan:
        print(f"First active item starts at rank: {active_plan[0].priority_rank}")

if __name__ == "__main__":
    debug_plan()
