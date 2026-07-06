# proc-mem-audit

## Purpose
Audit Linux process memory mappings for runtime integrity indicators.

## Features
- Lists executable mappings
- Detects writable + executable mappings
- Detects executable stack
- Detects non-file executable mappings
- Reports TracerPid
- Summarises suspicious mapping count and rule hits

## Example
./proc_mem_audit \<pid\>
./proc_mem_audit 12345

## Why this matters
Executable anonymous memory and WX mappings are useful indicators for runtime compromise or weak process hardening.

## Project context
Developed as part of research into runtime integrity verification for xApps in Open RAN Near-RT RIC environments.
