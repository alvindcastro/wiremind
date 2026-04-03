import asyncio
import argparse
import sys
import os
from wiremind.client import WiremindClient
from wiremind.agents.orchestrator import Orchestrator
from wiremind.state import ForensicsState
from wiremind.logger import configure_logger, get_logger

logger = get_logger("wiremind.main")

async def run_analysis(base_url: str, flow_id: str = None):
    """
    Run a full forensics analysis using the AI orchestrator.
    """
    configure_logger()
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
    
    logger.info("starting_ai_analysis", flow_id=flow_id, api_url=base_url)
    
    try:
        # Run the orchestrator
        final_state = await orchestrator.run(initial_state)
        
        logger.info("analysis_complete", findings_count=len(final_state['findings']))
        
        for finding in final_state['findings']:
            severity = finding.get('severity', 'UNKNOWN')
            agent = finding.get('agent', 'Unknown')
            description = finding.get('description', 'No description')
            logger.info("finding_detected", severity=severity, agent=agent, description=description)
            
    except Exception as e:
        logger.error("analysis_failed", error=str(e))
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Wiremind AI Forensics CLI")
    parser.add_argument("--url", default="http://localhost:8765", help="Wiremind API base URL")
    parser.add_argument("--flow", help="Specific Flow ID to analyze")
    
    args = parser.parse_args()
    
    asyncio.run(run_analysis(args.url, args.flow))

if __name__ == "__main__":
    main()
