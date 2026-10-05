from uuid import uuid4

from app.analysis.models import AnalysisResult, Finding, Severity
from app.analysis.rules import EXPECTED_BEHAVIOR, analyze_response_details
from app.execution.models import ExecutionResult
from app.fuzzing.models import FuzzCase


class ResponseAnalyzer:

    def analyze(
        self,
        execution: ExecutionResult,
        category: str,
        *,
        fuzz_case: FuzzCase | None = None,
    ) -> AnalysisResult:
        attack_metadata = fuzz_case.metadata if fuzz_case is not None else None
        assessment = analyze_response_details(
            response_body=execution.response_body or "",
            category=category,
            attack_metadata=attack_metadata,
            test_prompt=fuzz_case.prompt if fuzz_case is not None else None,
        )
        expected_behavior = str(
            (attack_metadata or {}).get("expected_behavior")
            or EXPECTED_BEHAVIOR.get(category)
            or "The target should follow the application's configured security policy."
        )
        observed_behavior = (
            assessment.observed_behavior
            if assessment is not None
            else "No target response was available for behavioral analysis."
        )
        vulnerable = assessment.vulnerable if assessment is not None else False
        indicators = assessment.indicators if assessment is not None else []
        attack_id = (attack_metadata or {}).get("attack_id")
        attack_name = (attack_metadata or {}).get("attack_name")

        findings: list[Finding] = []
        if assessment is not None and assessment.vulnerable:
            lineage = {
                "case_id": execution.case_id,
                "target_id": execution.target_id,
                "category": category,
                "attack_id": attack_id,
                "attack_category": (attack_metadata or {}).get("attack_category", category),
                "expected_behavior": expected_behavior,
                "observed_behavior": observed_behavior,
            }
            if fuzz_case is not None:
                lineage.update(
                    {
                        "parent_case_id": fuzz_case.parent_case_id,
                        "mutation_strategy": fuzz_case.mutation_strategy,
                        "mutation_depth": fuzz_case.mutation_depth,
                        "sequence_id": fuzz_case.sequence_id,
                        "origin_case_id": fuzz_case.metadata.get("origin_case_id"),
                        "ancestor_case_ids": list(
                            fuzz_case.metadata.get("ancestor_case_ids", [])
                        ),
                    }
                )
            relevant_metadata = {
                key: (attack_metadata or {})[key]
                for key in ("risk_area", "tags", "source", "safe_test")
                if key in (attack_metadata or {})
            }
            findings.append(
                Finding(
                    finding_id=str(uuid4()),
                    case_id=execution.case_id,
                    target_id=execution.target_id,
                    category=category,
                    title=f"Potential AI security boundary violation: {attack_name or category.replace('_', ' ')}",
                    severity=assessment.severity,
                    confidence=assessment.confidence,
                    evidence=assessment.evidence,
                    recommendation=assessment.recommendation,
                    attack_id=str(attack_id) if attack_id else None,
                    attack_category=str(
                        (attack_metadata or {}).get("attack_category") or category
                    ),
                    attack_name=str(attack_name) if attack_name else None,
                    expected_behavior=expected_behavior,
                    observed_behavior=observed_behavior,
                    indicator_type=indicators[0].indicator_type.value if indicators else None,
                    reproducibility=lineage,
                    metadata=relevant_metadata,
                )
            )

        return AnalysisResult(
            target_id=execution.target_id,
            case_id=execution.case_id,
            category=category,
            vulnerable=vulnerable,
            findings=findings,
            attack_id=str(attack_id) if attack_id else None,
            expected_behavior=expected_behavior,
            observed_behavior=observed_behavior,
            indicators=indicators,
        )


response_analyzer = ResponseAnalyzer()
