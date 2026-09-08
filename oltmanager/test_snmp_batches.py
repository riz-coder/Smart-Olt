import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import SimpleTestCase

from .utils import _snmp_get_oid_rows_chunked


class SnmpBatchTests(SimpleTestCase):
    def collect(self, replies, count=240, deadline=None):
        olt = SimpleNamespace(ip_address="127.0.0.1", snmp_port=161, snmp_community="test")
        engine = MagicMock()
        with patch("pysnmp.hlapi.asyncio.SnmpEngine", return_value=engine) as factory, \
                patch("pysnmp.hlapi.asyncio.UdpTransportTarget.create", new=AsyncMock()), \
                patch("pysnmp.hlapi.asyncio.get_cmd", new=AsyncMock(side_effect=replies)) as get:
            rows = _snmp_get_oid_rows_chunked(
                olt, [f"1.3.6.1.2.1.{i}" for i in range(count)], deadline_ts=deadline,
            )
        return rows, factory, engine, get

    def test_reuses_engine_across_batches(self):
        rows, factory, engine, get = self.collect([
            (None, 0, 0, [("1.3.6.1.2.1.0", 1)]),
            (None, 0, 0, [("1.3.6.1.2.1.120", 2)]),
        ])
        self.assertEqual(len(rows), 2)
        factory.assert_called_once()
        engine.close_dispatcher.assert_called_once()
        self.assertEqual(get.await_count, 2)

    def test_timeout_keeps_received_rows_and_closes_engine(self):
        rows, _, engine, _ = self.collect([
            (None, 0, 0, [("1.3.6.1.2.1.0", 1)]), asyncio.TimeoutError(),
        ])
        self.assertEqual(rows, {"1.3.6.1.2.1.0": "1"})
        engine.close_dispatcher.assert_called_once()

    def test_small_batch_fallback_uses_same_engine(self):
        rows, factory, engine, get = self.collect([
            ("tooBig", 0, 0, []),
            *[(None, 0, 0, [(f"1.3.6.1.2.1.{i}", 1)]) for i in range(4)],
        ], count=120)
        self.assertEqual(len(rows), 4)
        self.assertEqual(get.await_count, 5)
        factory.assert_called_once()
        engine.close_dispatcher.assert_called_once()

    def test_expired_budget_makes_no_requests(self):
        rows, factory, _, get = self.collect([], deadline=time.monotonic() - 1)
        self.assertEqual(rows, {})
        factory.assert_not_called()
        get.assert_not_called()
