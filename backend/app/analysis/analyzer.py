from uuid import uuid4

from app.analysis.models import AnalysisResult, Finding
from app.analysis.rules import analyze_response
from app.execution.models import ExecutionResult


class ResponseAnalyzer:

    def analyze(
        self,
        execution: ExecutionResult,
        category: str,
    ) -> AnalysisResult:

        result = analyze_response(
            response_body=execution.response_body or "",
            category=category,
        )

        if result is None:
            return AnalysisResult(
                target_id=execution.target_id,
                case_id=execution.case_id,
                category=category,
                vulnerable=False,
                findings=[],
            )

        vulnerable, severity, confidence, evidence, recommendation = result

        findings: list[Finding] = []

        if vulnerable:
            findings.append(
                Finding(
                    finding_id=str(uuid4()),
                    case_id=execution.case_id,
                    target_id=execution.target_id,
                    category=category,
                    title="Potential sensitive information disclosure",
                    severity=severity,
                    confidence=confidence,
                    evidence=evidence,
                    recommendation=recommendation,
                )
            )

        return AnalysisResult(
            target_id=execution.target_id,
            case_id=execution.case_id,
            category=category,
            vulnerable=vulnerable,
            findings=findings,
        )


response_analyzer = ResponseAnalyzer()
