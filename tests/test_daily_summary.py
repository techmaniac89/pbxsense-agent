from datetime import datetime, timedelta, timezone
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest
from unittest.mock import patch

from pbxsense_agent.daily_summary import DailySummaryTracker
from pbxsense_agent.engine import build_engine_signals
from pbxsense_agent.history import CdrCall
from pbxsense_agent.observations import PbxQueue, PbxSnapshot


class DailySummaryTest(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = str(Path(self.temp.name, 'summary.sqlite3'))
        self.start = datetime(2026, 10, 8, tzinfo=timezone.utc)

    def tracker(self, **options):
        return DailySummaryTracker(self.path, **options)

    def snapshot(self, calls=(), waiting=0, wait=0, **sources):
        return PbxSnapshot(True, 'test', recent_calls=list(calls), queues=[PbxQueue('support', waiting, wait)],
                           sources={name:{'state':state} for name,state in sources.items()})

    def call(self, number, disposition='ANSWERED', date=None):
        return CdrCall('private caller', 'private destination', disposition, date or self.start + timedelta(seconds=number),
                       30, channel=f'channel-{number}')

    def signals(self, facts, now=None):
        return build_engine_signals(endpoints=[], queues=[], recent_calls=[], voicemails=[], security_events=[],
            extension_names={}, now=now or self.start + timedelta(days=1, minutes=6), daily_summaries=facts)

    def test_recent_window_does_not_imply_day_coverage(self):
        tracker = self.tracker()
        facts = tracker.observe(self.snapshot([self.call(1)]), self.start + timedelta(hours=12))
        day = facts['days']['2026-10-08']
        self.assertFalse(day['callsComplete'])
        self.assertFalse(day['queuesComplete'])
        self.assertEqual(self.signals(facts), [])

    def test_observed_wait_breach_survives_clear_and_restart(self):
        tracker = self.tracker(queue_gap_seconds=90000, history_seconds=90000)
        tracker.observe(self.snapshot(waiting=1, wait=600), self.start)
        tracker.observe(self.snapshot(), self.start + timedelta(hours=23, minutes=59, seconds=59))
        reloaded = self.tracker(queue_gap_seconds=90000, history_seconds=90000)
        facts = reloaded.observe(self.snapshot(), self.start + timedelta(days=1, minutes=6))
        self.assertEqual(facts['days']['2026-10-08']['maxWait'], 600)
        self.assertNotIn('queues_finished_within_target', {signal['kind'] for signal in self.signals(facts)})

    def test_full_covered_queue_day_qualifies_only_after_midnight_settle(self):
        tracker = self.tracker(queue_gap_seconds=90000, history_seconds=90000)
        tracker.observe(self.snapshot(waiting=1, wait=40), self.start)
        tracker.observe(self.snapshot(), self.start + timedelta(hours=23, minutes=59))
        next_day = self.start + timedelta(days=1, minutes=6)
        facts = tracker.observe(self.snapshot(), next_day)
        self.assertIn('queues_finished_within_target', {s['kind'] for s in self.signals(facts, next_day)})
        self.assertNotIn('queues_finished_within_target', {s['kind'] for s in self.signals(facts, next_day.replace(minute=1))})

    def test_poll_gap_or_failed_queue_read_invalidates_whole_day(self):
        for snapshot in (self.snapshot(), self.snapshot(queues='temporarily_unavailable')):
            tracker = self.tracker()
            tracker.observe(self.snapshot(), self.start)
            facts = tracker.observe(snapshot, self.start + timedelta(seconds=20))
            self.assertFalse(facts['days']['2026-10-08']['queuesComplete'])

    def test_missed_call_is_not_erased_by_thousand_recent_answered_calls(self):
        tracker = self.tracker(queue_gap_seconds=90000, history_seconds=90000)
        missed = self.call(1, 'NO ANSWER')
        tracker.observe(self.snapshot([missed]), self.start)
        calls = [self.call(index) for index in range(2,1002)]
        facts = tracker.observe(self.snapshot(calls), self.start + timedelta(hours=1))
        self.assertEqual(facts['days']['2026-10-08']['missed'], 1)
        self.assertEqual(facts['days']['2026-10-08']['answered'], 1000)
        self.assertFalse(facts['days']['2026-10-08']['callsComplete'])
        self.assertNotIn('full_day_without_missed_calls', {s['kind'] for s in self.signals(facts)})

    def test_overlap_counts_once_across_refresh_and_restart(self):
        tracker = self.tracker()
        calls = [self.call(1), self.call(2)]
        tracker.observe(self.snapshot(calls), self.start)
        tracker.observe(self.snapshot(calls), self.start + timedelta(seconds=1))
        reloaded = self.tracker()
        facts = reloaded.observe(self.snapshot([*calls, self.call(3)]), self.start + timedelta(seconds=2))
        self.assertEqual(facts['days']['2026-10-08']['answered'], 3)
        self.assertEqual(facts['days']['2026-10-08']['firstAnswered'], '00:00:01')
        self.assertTrue(facts['days']['2026-10-08']['callsComplete'])

    def test_identical_records_use_multiplicity_not_one_hash(self):
        tracker = self.tracker()
        facts = tracker.observe(self.snapshot([self.call(1)] * 3), self.start)
        facts = tracker.observe(self.snapshot([self.call(1)] * 4), self.start + timedelta(seconds=1))
        self.assertEqual(facts['days']['2026-10-08']['answered'], 4)

    def test_new_queue_after_empty_inventory_is_partial_coverage(self):
        tracker = self.tracker()
        tracker.observe(PbxSnapshot(True, 'test'), self.start)
        facts = tracker.observe(self.snapshot(), self.start + timedelta(seconds=1))
        self.assertFalse(facts['days']['2026-10-08']['queuesComplete'])

    def test_clock_rollback_invalidates_current_day(self):
        tracker = self.tracker()
        tracker.observe(self.snapshot(), self.start + timedelta(days=1))
        facts = tracker.observe(self.snapshot(), self.start)
        self.assertFalse(facts['days']['2026-10-08']['callsComplete'])
        self.assertFalse(facts['days']['2026-10-08']['queuesComplete'])

    def test_corrupt_summary_does_not_break_observation(self):
        tracker = self.tracker()
        tracker.observe(self.snapshot(), self.start)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE state SET body = ?", ('{"identity":"' + tracker.identity + '","days":{"2026-10-08":{}}}',))
        facts = self.tracker().observe(self.snapshot(), self.start + timedelta(hours=1))
        self.assertTrue(facts['available'])
        self.assertFalse(facts['days']['2026-10-08']['callsComplete'])

    def test_cached_history_does_not_reingest_every_snapshot(self):
        tracker = self.tracker()
        tracker.observe(self.snapshot([self.call(1)]), self.start)
        snapshot = self.snapshot([self.call(1)])
        snapshot.sources['cdr'] = {'state':'ready', 'lastSuccessAgeSeconds':1}
        with patch.object(tracker, '_history', wraps=tracker._history) as history:
            tracker.observe(snapshot, self.start + timedelta(seconds=1))
        history.assert_not_called()

    def test_first_full_window_is_not_certified_as_complete(self):
        facts = self.tracker().observe(self.snapshot([self.call(i) for i in range(1000)]), self.start)
        self.assertFalse(facts['days']['2026-10-08']['callsComplete'])

    def test_ready_but_stale_history_is_not_coverage(self):
        tracker = self.tracker(queue_gap_seconds=90000)
        tracker.observe(self.snapshot(), self.start)
        snapshot = self.snapshot()
        snapshot.sources['cdr'] = {'state':'ready', 'lastSuccessAgeSeconds':300}
        facts = tracker.observe(snapshot, self.start + timedelta(seconds=300))
        self.assertFalse(facts['days']['2026-10-08']['callsComplete'])

    def test_identity_change_does_not_reuse_another_pbx_counts(self):
        self.tracker(identity='one').observe(self.snapshot([self.call(1)]), self.start)
        facts = self.tracker(identity='two').observe(self.snapshot([self.call(1)]), self.start)
        self.assertEqual(facts['days']['2026-10-08']['answered'], 1)

    def test_failed_transaction_cannot_double_count_on_retry(self):
        tracker = self.tracker()
        with patch.object(tracker, '_save', side_effect=sqlite3.OperationalError('disk failure')):
            facts = tracker.observe(self.snapshot([self.call(1)]), self.start)
        self.assertFalse(facts['available'])
        facts = tracker.observe(self.snapshot([self.call(1)]), self.start + timedelta(seconds=1))
        self.assertEqual(facts['days']['2026-10-08']['answered'], 1)

    def test_persisted_state_contains_no_caller_or_destination(self):
        self.tracker().observe(self.snapshot([self.call(1)]), self.start)
        data = Path(self.path).read_bytes()
        self.assertNotIn(b'private caller', data)
        self.assertNotIn(b'private destination', data)

    def test_complete_daily_summary_creates_no_missed_day_and_streak(self):
        days = {f'2026-10-{day:02}': {'callsComplete':True, 'calls':10, 'answered':10, 'missed':0,
                'voicemailComplete':True, 'voicemail':0} for day in (7,8)}
        facts = {'available':True, 'days':days, 'lastHistoryAt':(self.start + timedelta(days=1,minutes=6)).timestamp()}
        kinds = {s['kind'] for s in self.signals(facts)}
        self.assertIn('full_day_without_missed_calls', kinds)
        self.assertIn('clean_operating_day_streak', kinds)
        self.assertIn('voicemail_free_service_streak', kinds)
        days['2026-10-08']['calls'] = 0
        self.assertNotIn('full_day_without_missed_calls', {s['kind'] for s in self.signals(facts)})

    def test_partial_days_and_weeks_do_not_train_volume_milestones(self):
        now = datetime(2026,10,19,12,tzinfo=timezone.utc)
        days = {(now.date()-timedelta(days=offset)).isoformat(): {'callsComplete':True,'answered':10} for offset in range(15)}
        days[now.date().isoformat()]['answered'] = 100
        facts = {'available':True,'days':days,'lastHistoryAt':now.timestamp()}
        signals = self.signals(facts, now)
        periods = {s['technical'].get('period') for s in signals if s['kind']=='adaptive_call_volume_milestone'}
        self.assertIn('weekly', periods)
        days.pop('2026-10-06')
        periods = {s['technical'].get('period') for s in self.signals(facts, now) if s['kind']=='adaptive_call_volume_milestone'}
        self.assertNotIn('weekly', periods)

    def test_monthly_baselines_require_complete_months_not_fifteen_sampled_days(self):
        now = datetime(2026,10,1,12,tzinfo=timezone.utc)
        days = {}
        date = datetime(2026,8,1).date()
        while date <= now.date():
            days[date.isoformat()] = {'callsComplete':True,'answered':1}
            date += timedelta(days=1)
        days['2026-10-01']['answered'] = 40
        facts = {'available':True,'days':days,'lastHistoryAt':now.timestamp()}
        periods = {s['technical'].get('period') for s in self.signals(facts, now) if s['kind']=='adaptive_call_volume_milestone'}
        self.assertIn('monthly', periods)
        days['2026-08-05']['callsComplete'] = False
        periods = {s['technical'].get('period') for s in self.signals(facts, now) if s['kind']=='adaptive_call_volume_milestone'}
        self.assertNotIn('monthly', periods)
