"""Reporter JUnit XML (cada hallazgo es un testcase fallido)."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from sastcore.findings.model import Finding


class JUnitReporter:
    """Genera un informe JUnit XML consumible por CI."""

    def render(self, findings: list[Finding], *, files_scanned: int) -> str:
        testsuites = ET.Element("testsuites")
        testsuite = ET.SubElement(
            testsuites,
            "testsuite",
            {
                "name": "sastcore",
                "tests": str(len(findings)),
                "failures": str(len(findings)),
            },
        )
        for finding in findings:
            location = f"{finding.location.path}:{finding.location.start_line}"
            testcase = ET.SubElement(
                testsuite,
                "testcase",
                {"classname": finding.rule_id, "name": location},
            )
            failure = ET.SubElement(
                testcase,
                "failure",
                {"message": finding.message, "type": finding.severity.value},
            )
            details = [f"{finding.severity.value} {finding.rule_id} en {location}", finding.snippet]
            if finding.data_flow:
                details.append("Flujo de datos:")
                details.extend(
                    f"  {s.location.path}:{s.location.start_line} - {s.message}"
                    for s in finding.data_flow
                )
            failure.text = "\n".join(details)
        ET.indent(testsuites)
        return ET.tostring(testsuites, encoding="unicode", xml_declaration=True)
