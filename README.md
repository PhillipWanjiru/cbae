# CDIS Binary Analysis Engine (CBAE)

**A Domain-Specific Binary Analysis and Driver Translation Tool**

## Overview

The CDIS Binary Analysis Engine (CBAE) is a specialized binary analysis system developed as the intelligence core of the Cross-Platform Driver Intelligence System (CDIS).

CBAE is designed to analyze Windows kernel driver binaries and Linux kernel modules, understand their hardware interaction behaviour, extract structured machine-readable specifications, and support driver translation across operating system boundaries.

Unlike general-purpose binary analysis platforms, CBAE focuses specifically on kernel-mode device drivers and their hardware-level operations.

## Core Objectives

- Parse Windows PE32+ driver binaries and Linux ELF64 kernel modules.
- Disassemble x86-64 machine code and construct control flow graphs.
- Develop the CDIS Intermediate Representation (CIR) for semantic driver analysis.
- Identify kernel API calls and hardware interaction patterns.
- Perform data flow analysis and type recovery.
- Decompile analyzed driver functions into readable C pseudocode.
- Generate Driver DNA fingerprints for behavioural comparison.
- Support behavioural capture and analysis of closed-source drivers.
- Enable cross-OS API substitution between Windows and Linux.
- Provide automated batch processing of driver repositories.

## Key Components

### 1. Binary Parsing Engine
Processes PE32+ and ELF64 formats, extracting sections, symbols, imports, exports and relocation information.

### 2. CDIS Intermediate Representation (CIR)
A driver-aware intermediate representation that gives hardware operations explicit semantic meaning, including:

- Memory-mapped I/O (MMIO)
- Direct Memory Access (DMA)
- Interrupt management (IRQ)
- PCI configuration access
- Kernel API operations
- Synchronization and power management

### 3. Disassembly and Control Flow Analysis
Uses Capstone to decode x86-64 instructions and construct basic block graphs and function call graphs.

### 4. Semantic Analysis
Performs API recognition, data flow analysis, type recovery, driver lifecycle identification and hardware interaction classification.

### 5. Decompiler
Transforms CIR-level representations into readable C pseudocode for analysis and translation.

### 6. Driver DNA
Extracts 512-dimensional behavioural fingerprints to support driver equivalence detection and compatibility analysis.

### 7. Behavioural Capture Pipeline
Provides a runtime analysis approach for observing hardware interactions in controlled virtual machine environments.

### 8. Cross-OS API Substitution
Maps recognized Windows and Linux kernel operations to their corresponding target operating system interfaces.

### 9. Batch Processing
Supports automated analysis, parallel execution, result persistence and incremental reanalysis of driver versions.

## Technology Stack

| Technology | Purpose |
|---|---|
| C | Binary parsing and low-level analysis |
| C++ | Decompiler and program analysis |
| Java | Ghidra integration and batch processing |
| Python | Post-analysis processing and scoring |
| Capstone | x86-64 disassembly |
| LLVM | Compilation and code generation |
| Clang | C source and AST analysis |
| QEMU/KVM | Virtual machine behavioural capture |
| Frida | Runtime instrumentation |
| SQLite | Analysis result persistence |

## Supported Platforms

- Windows kernel drivers (PE32+)
- Linux kernel modules (ELF64)
- x86-64 architecture
- ARM64 planned as a future extension

## Project Architecture

CBAE follows a pipeline-oriented architecture:

1. Binary Loading and Parsing
2. Disassembly and CFG Construction
3. CIR Lifting
4. API Recognition
5. Data Flow and Type Recovery
6. Driver Lifecycle Analysis
7. Hardware Interaction Classification
8. Decompilation
9. Driver DNA Extraction
10. Behavioural Capture
11. Cross-OS API Substitution
12. Batch Processing and Result Storage

## Research Context

CBAE is a research and development project focused on domain-specific binary analysis, kernel driver intelligence and cross-platform software interoperability.

It is developed as part of the CDIS initiative.

## Development Status

CBAE has reached **Phase 5 implementation**.

The repository contains the implementation and supporting tests for major subsystems, including:

- PE and ELF binary loading
- Disassembly and control-flow graph construction
- CDIS Intermediate Representation (CIR)
- Data-flow analysis and SSA verification
- Database persistence
- Rust-based batch processing and inter-process communication

Phase-specific design and implementation records are maintained in `docs/architecture/`, including `PHASE3.md`, `PHASE4.md` and `PHASE5.md`.

Development beyond Phase 5, integration testing and further validation should be tracked against the project's implementation roadmap.

## Responsible Use

CBAE is intended for legitimate systems research, driver compatibility engineering, interoperability analysis and authorized binary examination.

All analysis should respect applicable intellectual property laws, software licensing requirements and responsible security research practices.

## Author

**Phillip Wanjiru**

Meru University of Science and Technology

Email: majorsergeant019@gmail.com

## License

No open-source license has been specified yet. All rights remain with their respective owners unless a license is subsequently added.
