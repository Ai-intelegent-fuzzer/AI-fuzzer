# AI Attack Library

## Conceptual architecture

AI Attack Library
        ↓
Semantic Security Test
        ↓
Mutation Engine
        ↓
Target Execution
        ↓
Response Analysis
        ↓
Potential Finding

The AI Attack Library is the semantic layer that defines what behavior is being tested. It models attack categories such as prompt injection, role confusion, data leakage, retrieval poisoning, and tool misuse. The library is intentionally deterministic and synthetic: it uses safe canary markers such as `[TEST_CANARY]`, `[SYNTHETIC_SECRET]`, `[SYNTHETIC_SYSTEM_PROMPT]`, and `[SYNTHETIC_USER_DATA]` without attempting real credential theft or unauthorized exploitation.

## Attack Library vs Mutation Engine

The Attack Library answers the question: "What AI security behavior are we testing?"

The Mutation Engine answers the question: "How do we vary the test while keeping it within the existing execution contract?"

This separation keeps the system honest. The attack definition describes the security intention and expected behavior. The mutation engine then applies deterministic transformations to produce variations of the same semantic test while preserving lineage metadata and the existing `FuzzCase` structure.

## Why this differs from a traditional web fuzzer

A traditional web fuzzer varies payload bytes to trigger parser or protocol defects. This system is not trying to brute-force raw HTTP or database input. Instead, it tests AI-system trust boundaries, instruction precedence, retrieval trust, role authority, and tool-scoping behavior.

The core principle is semantic testing of decision-making, not raw input fuzzing. The same fuzzing execution pipeline is still used, but the payload semantics are higher-level and security-specific to AI applications.

## Attack categories in scope

- prompt_injection
- instruction_override
- jailbreak
- context_manipulation
- data_leakage
- rag_security
- indirect_prompt_injection
- tool_misuse
- unauthorized_agent_action
- role_confusion

## Safety posture

The library is designed for controlled, local testing only. It avoids destructive actions, persistence attempts, malware generation, credential theft, or real-world exploitation. Every test is synthetic and evaluated heuristically against the target's response body rather than treated as a confirmed exploit.
