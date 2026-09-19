# Phase 1 CLI Demonstration

This script provides an interactive terminal walkthrough of the TRC Engine's Threat Agent Reasoning Loop (Phase 1).

## Usage

Run the script from the project root:

```bash
python scripts/demo_cli.py
```

## Faculty Notes (Phase 1 Disclosure)

Please note the following constraints when presenting this to faculty:
- **Scenario Generation (Stage 4)** currently uses a deterministic JSON fixture for reproducibility during this demo. Live OpenAI API integration will land in Week 3.
- **Protocol Invariant Validation (Stage 5)** demonstrates schema completeness and evidence verification, but custom complex rules will be expanded in later phases.
- The **FAISS Retrieval** runs locally entirely on-CPU and executes live queries against our embedded knowledge base.
