---
name: auth_bypass_forger
description: Advanced methodology for structuring Download Agent (DA) payloads, bypassing SLA/DAA (Serial Link Authentication), and managing MediaTek checksums.
---

SECURITY BYPASS ARCHITECTURE: When designing payloads or dealing with secure boot/SLA protections:
1. CHECKSUM RIGIDITY: Never suggest arbitrary byte modifications. Any change to a payload must be accompanied by an automated script to recalculate and append the correct MTK Checksum.
2. SIGNATURE STRIPPING: If SLA/DAA is active, analyze the structure to find where the signature validation occurs in the DA. Propose memory patching strategies (e.g., changing conditional jumps in ARM hex) to bypass the check.
3. PAYLOAD INJECTION: Structure the Python code to send the payload in architecturally correct chunk sizes based on the memory constraints of the target SRAM.
4. DEPENDENCY CHECK: Instruct Node 1 to search the 'docs_forensics' folder for existing exploit chains (like kamakiri or exploit payloads) before inventing a new bypass from scratch.