from uuid import uuid4

from app.analysis.models import AnalysisResult, AnalysisStatus, Finding, Severity
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
        execution_completed = execution.status == "completed"
        status = (
            assessment.status
            if execution_completed and assessment is not None
            else AnalysisStatus.INCONCLUSIVE
        )
        vulnerable = (
            assessment.vulnerable
            if execution_completed and assessment is not None
            else False
        )
        indicators = assessment.indicators if assessment is not None else []
        attack_id = (attack_metadata or {}).get("attack_id")
        attack_name = (attack_metadata or {}).get("attack_name")

        finding_type = (
            indicators[0].indicator_type.value.replace("_", " ").title()
            if indicators
            else category.replace("_", " ").title()
        )

        findings: list[Finding] = []
        if execution_completed and assessment is not None and assessment.vulnerable:
            lineage = {
                "case_id": execution.case_id,
                "target_id": execution.target_id,
                "provider": execution.provider,
                "model": execution.model,
                "execution_status": execution.status,
                "response_truncated": execution.response_truncated,
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
            primary_verification_level = (
                indicators[0].metadata.get(
                    "verification_level", "response_behavior_observed"
                )
                if indicators
                else "response_behavior_observed"
            )
            relevant_metadata["evidence_assurance"] = primary_verification_level
            relevant_metadata["external_impact_verified"] = any(
                indicator.metadata.get("external_impact_verified") is True
                for indicator in indicators
            )
            relevant_metadata["indicators"] = [
                {
                    "indicator_type": indicator.indicator_type.value,
                    "description": indicator.description,
                    "evidence": indicator.evidence,
                    "confidence": indicator.confidence.value,
                    "category": indicator.category,
                    "metadata": indicator.metadata,
                }
                for indicator in indicators
            ]
            findings.append(
                Finding(
                    finding_id=str(uuid4()),
                    case_id=execution.case_id,
                    target_id=execution.target_id,
                    category=category,
                    title=(
                        f"{finding_type}"
                        f" [response claim only; external impact unverified]"
                        f": {attack_name or category.replace('_', ' ')}"
                        if primary_verification_level == "response_claim_only"
                        else f"{finding_type}: {attack_name or category.replace('_', ' ')}"
                    ),
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
            status=status,
            findings=findings,
            attack_id=str(attack_id) if attack_id else None,
            expected_behavior=expected_behavior,
            observed_behavior=observed_behavior,
            indicators=indicators,
        )


response_analyzer = ResponseAnalyzer()
