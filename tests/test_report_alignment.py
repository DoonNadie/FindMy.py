"""Offline reproductions of upstream #273 and #274 (not fixes)."""

import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from findmy.accessory import FindMyAccessory


class ReportAlignmentReproductions(unittest.TestCase):
    def setUp(self):
        self.start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.interval = timedelta(minutes=15)
        self.accessory = SimpleNamespace(
            _alignment_date=self.start, _alignment_index=235, interval=self.interval
        )

    def test_274_valid_report_outside_current_search_ceiling(self):
        query_time = self.start + 69 * self.interval
        ceiling = FindMyAccessory.get_max_index(self.accessory, query_time)
        available_reports = {303: "older", 329: "newer"}
        visible = [report for index, report in available_reports.items() if index <= ceiling]
        self.assertEqual(visible, ["older"])
        self.assertEqual(ceiling, 304)

    def test_273_highest_secondary_candidate_prevents_lower_alignment(self):
        report_time = self.start + self.interval
        for index in sorted({395, 300}, reverse=True):
            FindMyAccessory.update_alignment(self.accessory, report_time, index)
        FindMyAccessory.update_alignment(self.accessory, report_time + self.interval, 301)
        self.assertEqual(self.accessory._alignment_index, 395)
        self.assertEqual(self.accessory._alignment_date, report_time)
