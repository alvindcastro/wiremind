import asyncio
import argparse
import sys
import os
from wiremind.client import WiremindClient
from wiremind.agents.orchestrator import Orchestrator
from wiremind.state import ForensicsState

async def run_analysis(base_url: str, flow_id: str = None):
    """
    Run a full forensics analysis using the AI orchestrator.
    """
    client = WiremindClient(base_url)
    orchestrator = Orchestrator(client)
    
    # Initialize state
    initial_state = ForensicsState(
        flow_id=flow_id,
        messages=[],
        findings=[],
        context={},
        next_agent="orchestrator"
    )
    
    print(f"[*] Starting AI analysis for flow: {flow_id if flow_id else 'All'}")
    print(f"[*] Connecting to API at: {base_url}")
    
    try:
        # Run the orchestrator
        # Note: In a real scenario, this would loop or use LangGraph's .invoke()
        # For the CLI entry point, we use a simplified invocation
        final_state = await orchestrator.run(initial_state)
        
        print("\n[+] Analysis Complete!")
        print(f"[+] Total Findings: {len(final_state['findings'])}")
        
        for finding in final_state['findings']:
            severity = finding.get('severity', 'UNKNOWN')
            agent = finding.get('agent', 'Unknown')
            description = finding.get('description', 'No description')
            print(f"  [{severity}] {agent}: {description}")
            
    except Exception as e:
        print(f"[!] Error during analysis: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Wiremind AI Forensics CLI")
    parser.add_argument("--url", default="http://localhost:8765", help="Wiremind API base URL")
    parser.add_argument("--flow", help="Specific Flow ID to analyze")
    
    args = parser.parse_args()
    
    asyncio.run(run_analysis(args.url, args.flow))

if __name__ == "__main__":
    main()
