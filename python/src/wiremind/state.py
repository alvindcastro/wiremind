from typing import Annotated, List, Dict, Any, TypedDict
import operator

class ForensicsState(TypedDict):
    # The current set of enriched flows being analyzed
    flows: List[Dict[str, Any]]
    
    # Findings from specialist agents (e.g., DNS, TLS, HTTP)
    findings: Annotated[List[Dict[str, Any]], operator.add]
    
    # The current task or question being investigated
    current_task: str
    
    # Evidence graph (correlations between flows/findings)
    evidence: Dict[str, Any]
    
    # Next steps for the orchestrator
    next_steps: List[str]
    
    # Final summary of the attack chain
    summary: str
