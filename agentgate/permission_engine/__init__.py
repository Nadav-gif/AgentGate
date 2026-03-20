"""Permission engine — evaluates IAM policies to answer 'can this identity do this?'"""

from agentgate.permission_engine.evaluator import can_do
from agentgate.permission_engine.models import Decision, EvaluationResult

__all__ = ["can_do", "Decision", "EvaluationResult"]
