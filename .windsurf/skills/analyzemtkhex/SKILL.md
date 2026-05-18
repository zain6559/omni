---
name: analyzemtkhex
description: Triggers whenever raw hex values, memory dumps, or MediaTek DA payloads need to be parsed, mapped, and analyzed for structural vulnerabilities or magic headers.
---

CRITICAL FORENSIC PROTOCOL: When tasked with analyzing memory dumps, DA (Download Agent) payloads, or raw hex values, strictly forbid high-level summaries. 
1. AUTOMATION: Instantly write a Python script using 'struct', 'binascii', and 're' to parse the payload.
2. TARGETED HUNTING: Program the script to search for MTK-specific magic headers (e.g., EMMC_BOOT, UFS_LUN, BROM signatures) and extract their exact offset, size, and endianness.
3. EXECUTION & MAPPING: Run the script locally via the terminal. Read the output and generate a precise 'Memory Map Table' (Address | Hex Value | ASCII | Architectural Implication).
4. VULNERABILITY CONTEXT: Cross-reference the discovered offsets with any available datasheets in the 'docs_forensics' directory to identify potential overflow vectors or bypass points.