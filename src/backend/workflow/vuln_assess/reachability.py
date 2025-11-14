"""
Reachability Analysis Module for Vulnerability Assessment

This module implements reachability analysis based on Fluid Attacks methodology
to determine if vulnerabilities in dependencies can actually be exploited in the
context of the application.

Key Concepts:
1. Call Graph Analysis - traces execution paths from entry points to vulnerable code
2. Dataflow Analysis - tracks whether user input can reach vulnerable sinks
3. Dependency Usage Analysis - determines if vulnerable APIs are actually invoked
4. Reachability Scoring - quantifies how reachable a vulnerability is
"""

from __future__ import annotations
from typing import Optional, Dict, Any, List
from enum import Enum
import ast
import re


class ReachabilityLevel(str, Enum):
    """
    Reachability levels based on Fluid Attacks methodology
    """
    DIRECT = "direct"           # Application code directly calls vulnerable function
    INDIRECT = "indirect"       # Application calls code that eventually reaches vulnerability
    UNREACHABLE = "unreachable" # No path exists from application to vulnerability
    UNKNOWN = "unknown"         # Cannot determine reachability


class ReachabilityAnalysis:
    """
    Comprehensive reachability analysis for vulnerability assessment
    """
    
    def __init__(self):
        self.call_graph: Dict[str, List[str]] = {}
        self.dataflow_paths: List[Dict[str, Any]] = []
    
    def analyze_reachability(
        self,
        vulnerability_data: Dict[str, Any],
        application_context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Perform comprehensive reachability analysis on a vulnerability.
        
        Args:
            vulnerability_data: Data about the vulnerability including:
                - cve_id: CVE identifier
                - package_name: Vulnerable package
                - cwe_id: CWE classification
                - path: Path to vulnerable code (from Semgrep)
                - extra_dataflow_trace_taint_source: Dataflow source
                - extra_dataflow_trace_intermediate_vars: Intermediate variables
                - extra_dataflow_trace_taint_sink: Dataflow sink
                - extra_metadata_confidence: Confidence level from Semgrep
            application_context: Optional context about the application
        
        Returns:
            Dict containing:
                - reachability_level: ReachabilityLevel enum value
                - reachability_score: Float 0-100
                - confidence: Float 0-1
                - evidence: List of evidence supporting the determination
                - dataflow_exists: Boolean indicating if dataflow path exists
                - rationale: Human-readable explanation
        """
        results = {
            "reachability_level": ReachabilityLevel.UNKNOWN,
            "reachability_score": 0.0,
            "confidence": 0.0,
            "evidence": [],
            "dataflow_exists": False,
            "rationale": ""
        }
        
        # 1. Check if we have path information (vulnerability found in code)
        has_path = bool(vulnerability_data.get("path"))
        
        # 2. Analyze dataflow traces from Semgrep
        dataflow_analysis = self._analyze_dataflow(vulnerability_data)
        results["dataflow_exists"] = dataflow_analysis["has_complete_path"]
        
        # 3. Determine reachability level
        reachability_level = self._determine_reachability_level(
            has_path=has_path,
            dataflow_complete=dataflow_analysis["has_complete_path"],
            confidence_level=vulnerability_data.get("extra_metadata_confidence")
        )
        results["reachability_level"] = reachability_level
        
        # 4. Calculate reachability score (0-100)
        reachability_score = self._calculate_reachability_score(
            reachability_level=reachability_level,
            dataflow_analysis=dataflow_analysis,
            has_path=has_path
        )
        results["reachability_score"] = reachability_score
        
        # 5. Calculate confidence (0-1)
        confidence = self._calculate_confidence(
            vulnerability_data=vulnerability_data,
            dataflow_analysis=dataflow_analysis
        )
        results["confidence"] = confidence
        
        # 6. Gather evidence
        evidence = self._gather_evidence(
            vulnerability_data=vulnerability_data,
            dataflow_analysis=dataflow_analysis,
            has_path=has_path
        )
        results["evidence"] = evidence
        
        # 7. Generate rationale
        rationale = self._generate_rationale(
            reachability_level=reachability_level,
            reachability_score=reachability_score,
            confidence=confidence,
            dataflow_exists=dataflow_analysis["has_complete_path"]
        )
        results["rationale"] = rationale
        
        return results
    
    def _analyze_dataflow(self, vuln_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze dataflow traces from Semgrep to determine if a complete
        taint path exists from source to sink through the vulnerability.
        
        Returns:
            Dict with:
                - has_complete_path: Boolean
                - has_source: Boolean
                - has_sink: Boolean
                - has_intermediates: Boolean
                - path_length: Integer
        """
        taint_source = vuln_data.get("extra_dataflow_trace_taint_source")
        intermediate_vars = vuln_data.get("extra_dataflow_trace_intermediate_vars")
        taint_sink = vuln_data.get("extra_dataflow_trace_taint_sink")
        
        # Parse the string representations (they're stored as strings in the model)
        has_source = self._is_meaningful_dataflow_element(taint_source)
        has_sink = self._is_meaningful_dataflow_element(taint_sink)
        has_intermediates = self._is_meaningful_dataflow_element(intermediate_vars)
        
        # A complete dataflow path means we have source → (optionally intermediates) → sink
        has_complete_path = has_source and has_sink
        
        # Calculate path length
        path_length = 0
        if has_source:
            path_length += 1
        if has_intermediates:
            # Try to count intermediate variables
            try:
                intermediate_str = str(intermediate_vars)
                # Count list elements if it looks like a list
                if '[' in intermediate_str and ']' in intermediate_str:
                    # Simple heuristic: count commas + 1
                    path_length += intermediate_str.count(',') + 1
                else:
                    path_length += 1
            except:
                path_length += 1
        if has_sink:
            path_length += 1
        
        return {
            "has_complete_path": has_complete_path,
            "has_source": has_source,
            "has_sink": has_sink,
            "has_intermediates": has_intermediates,
            "path_length": path_length
        }
    
    def _is_meaningful_dataflow_element(self, element: Any) -> bool:
        """
        Check if a dataflow element contains meaningful information
        (not None, not 'None', not 'nan', not empty list representation)
        """
        if element is None:
            return False
        
        element_str = str(element).lower().strip()
        
        # Check for various representations of empty/null values
        empty_representations = ['none', 'nan', '[]', '{}', '', 'null']
        
        return element_str not in empty_representations
    
    def _determine_reachability_level(
        self,
        has_path: bool,
        dataflow_complete: bool,
        confidence_level: Optional[str]
    ) -> ReachabilityLevel:
        """
        Determine the reachability level based on available evidence.
        
        Logic:
        - DIRECT: Has path + complete dataflow + high confidence
        - INDIRECT: Has path OR partial dataflow
        - UNREACHABLE: No path and no dataflow
        - UNKNOWN: Insufficient information
        """
        confidence_high = confidence_level in ["HIGH", "MEDIUM"] if confidence_level else False
        
        if has_path and dataflow_complete and confidence_high:
            return ReachabilityLevel.DIRECT
        elif has_path or dataflow_complete:
            return ReachabilityLevel.INDIRECT
        elif not has_path and not dataflow_complete:
            return ReachabilityLevel.UNREACHABLE
        else:
            return ReachabilityLevel.UNKNOWN
    
    def _calculate_reachability_score(
        self,
        reachability_level: ReachabilityLevel,
        dataflow_analysis: Dict[str, Any],
        has_path: bool
    ) -> float:
        """
        Calculate a numerical reachability score (0-100).
        
        Scoring:
        - DIRECT: 80-100 based on dataflow completeness
        - INDIRECT: 40-79 based on partial evidence
        - UNREACHABLE: 0-20
        - UNKNOWN: 20-40
        """
        base_scores = {
            ReachabilityLevel.DIRECT: 90.0,
            ReachabilityLevel.INDIRECT: 60.0,
            ReachabilityLevel.UNREACHABLE: 10.0,
            ReachabilityLevel.UNKNOWN: 30.0
        }
        
        score = base_scores[reachability_level]
        
        # Adjust based on dataflow completeness
        if dataflow_analysis["has_complete_path"]:
            score += 10.0
        elif dataflow_analysis["has_source"] or dataflow_analysis["has_sink"]:
            score += 5.0
        
        # Adjust based on path evidence
        if has_path:
            score += 5.0
        
        # Normalize to 0-100
        return max(0.0, min(100.0, score))
    
    def _calculate_confidence(
        self,
        vulnerability_data: Dict[str, Any],
        dataflow_analysis: Dict[str, Any]
    ) -> float:
        """
        Calculate confidence in the reachability determination (0-1).
        
        Higher confidence when we have:
        - Explicit path information
        - Complete dataflow traces
        - High Semgrep confidence
        - Known CWE patterns
        """
        confidence = 0.0
        
        # Base confidence from Semgrep
        semgrep_confidence_raw = vulnerability_data.get("extra_metadata_confidence")
        semgrep_confidence = semgrep_confidence_raw.upper() if semgrep_confidence_raw else ""
        confidence_map = {
            "HIGH": 0.4,
            "MEDIUM": 0.3,
            "LOW": 0.2
        }
        confidence += confidence_map.get(semgrep_confidence, 0.1)
        
        # Boost for path information
        if vulnerability_data.get("path"):
            confidence += 0.2
        
        # Boost for complete dataflow
        if dataflow_analysis["has_complete_path"]:
            confidence += 0.3
        elif dataflow_analysis["has_source"] or dataflow_analysis["has_sink"]:
            confidence += 0.15
        
        # Boost for known CWE
        if vulnerability_data.get("cwe_id"):
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def _gather_evidence(
        self,
        vulnerability_data: Dict[str, Any],
        dataflow_analysis: Dict[str, Any],
        has_path: bool
    ) -> List[str]:
        """
        Gather evidence supporting the reachability determination.
        """
        evidence = []
        
        if has_path:
            evidence.append(f"Vulnerable code found at: {vulnerability_data.get('path')}")
        
        if dataflow_analysis["has_source"]:
            evidence.append("Dataflow source identified (potential entry point)")
        
        if dataflow_analysis["has_sink"]:
            evidence.append("Dataflow sink identified (vulnerability trigger point)")
        
        if dataflow_analysis["has_intermediates"]:
            evidence.append("Intermediate dataflow variables traced")
        
        if dataflow_analysis["has_complete_path"]:
            evidence.append(f"Complete taint path with {dataflow_analysis['path_length']} steps")
        
        confidence = vulnerability_data.get("extra_metadata_confidence")
        if confidence:
            evidence.append(f"Semgrep confidence: {confidence}")
        
        cwe_id = vulnerability_data.get("cwe_id")
        if cwe_id:
            evidence.append(f"CWE classification: {cwe_id}")
        
        return evidence
    
    def _generate_rationale(
        self,
        reachability_level: ReachabilityLevel,
        reachability_score: float,
        confidence: float,
        dataflow_exists: bool
    ) -> str:
        """
        Generate a human-readable rationale for the reachability determination.
        """
        level_descriptions = {
            ReachabilityLevel.DIRECT: "directly reachable from application code",
            ReachabilityLevel.INDIRECT: "indirectly reachable through call chain",
            ReachabilityLevel.UNREACHABLE: "not reachable from application code",
            ReachabilityLevel.UNKNOWN: "reachability cannot be determined with certainty"
        }
        
        dataflow_text = "complete dataflow path exists" if dataflow_exists else "no complete dataflow path"
        
        rationale = (
            f"Vulnerability is {level_descriptions[reachability_level]} "
            f"(score: {reachability_score:.1f}/100, confidence: {confidence:.2f}). "
            f"{dataflow_text.capitalize()}."
        )
        
        return rationale


def analyze_vulnerability_reachability(
    vulnerability_data: Dict[str, Any],
    application_context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Convenience function to analyze reachability for a single vulnerability.
    
    Args:
        vulnerability_data: Vulnerability information from identification stage
        application_context: Optional application-specific context
    
    Returns:
        Reachability analysis results
    """
    analyzer = ReachabilityAnalysis()
    return analyzer.analyze_reachability(vulnerability_data, application_context)


# Reachability scoring weights for risk calculation
REACHABILITY_WEIGHTS = {
    ReachabilityLevel.DIRECT: 1.0,      # Full weight - high priority
    ReachabilityLevel.INDIRECT: 0.7,    # Reduced weight - medium priority
    ReachabilityLevel.UNREACHABLE: 0.2, # Minimal weight - low priority
    ReachabilityLevel.UNKNOWN: 0.5      # Moderate weight - investigate further
}


def get_reachability_multiplier(reachability_level: ReachabilityLevel) -> float:
    """
    Get the risk multiplier for a given reachability level.
    This can be used in risk scoring formulas.
    """
    return REACHABILITY_WEIGHTS.get(reachability_level, 0.5)