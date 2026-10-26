"""Docker-free checks for ownership assertion diagnostics."""

import subprocess
import unittest

from test_container import _ownership_members


class OwnershipDiagnosticTests(unittest.TestCase):
    def check_failure(self, report, code=0, expected=0):
        result = subprocess.CompletedProcess(["private-canary"], code,
                                             stdout=b"private-canary", stderr=b"private-canary")
        with self.assertRaises(AssertionError) as caught:
            _ownership_members(self, result, report, expected)
        text = str(caught.exception)
        self.assertNotIn("private-canary", text)
        self.assertIn(f"exit={code}", text)
        return text

    def test_exit_is_checked_before_missing_report(self):
        self.assertIn("0 != 3", self.check_failure(None, code=3))

    def test_missing_report(self):
        self.assertIn("report=0 status=unknown reason=unknown inspection=0 members=-1",
                      self.check_failure(None))

    def test_public_failure_report(self):
        self.assertIn("report=1 status=failed reason=input-failed inspection=0 members=-1",
                      self.check_failure({"status": "failed", "diagnostics": ["input-failed"],
                                          "context": {"private-canary": "private-canary"}}, code=3))

    def test_missing_inspection(self):
        self.assertIn("status=partial reason=unknown inspection=0 members=-1",
                      self.check_failure({"status": "partial", "diagnostics": ["private-canary"]}))

    def test_malformed_structures_are_not_printed(self):
        for report in ("private-canary", {"inspection": "private-canary"},
                       {"inspection": {"members": "private-canary"}},
                       {"inspection": {"members": []}},
                       {"inspection": {"members": [{}, "private-canary"]}},
                       {"status": "private-canary", "diagnostics": "private-canary"}):
            with self.subTest(shape=type(report).__name__):
                self.check_failure(report)

    def test_valid_members_are_returned_for_both_expected_exits(self):
        members = [{"private-canary": "private-canary"}, {}]
        for code in (0, 1):
            result = subprocess.CompletedProcess([], code)
            self.assertIs(members, _ownership_members(self, result,
                          {"status": "successful", "inspection": {"members": members}}, code))
