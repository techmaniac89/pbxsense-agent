import copy
import unittest

from pbxsense_agent.relay_notification_policy import RelayNotificationPolicy


def phone(number):
    return {
        "id": f"sig_endpoint_{number}_unavailable",
        "kind": "endpoint_unavailable", "state": "active",
        "category": "health", "importance": "attention",
        "title": f"Phone {number} looks unavailable", "body": "Unreachable",
    }


class RelayNotificationPolicyTests(unittest.TestCase):
    def setUp(self):
        self.state = {}
        self.events = []
        self.phones = [phone(number) for number in ("101", "102", "103")]

    def observe(self, signals, now=100, total=3, connected=True):
        # Recreate the policy to verify all continuity resides in durable state.
        RelayNotificationPolicy(self.state, self.events.append).observe(
            signals, now=now, total_phones=total, connection_ok=connected,
        )

    def test_one_phone_and_two_phone_boundaries(self):
        self.observe(self.phones[:1], total=1)
        self.observe(self.phones[:1], now=109, total=1)
        self.assertEqual(self.events, [])
        self.observe(self.phones[:1], now=110, total=1)
        self.assertEqual(len(self.events), 1)
        self.state = {}
        self.events.clear()
        self.observe(self.phones[:2])
        self.observe(self.phones[:2], now=114.99)
        self.assertEqual(self.events, [])
        self.observe(self.phones[:2], now=115)
        self.assertEqual(len(self.events), 1)
        self.assertEqual(self.events[0]["title"], "2 phones look unavailable")

    def test_shared_incident_update_and_stable_recovery(self):
        self.observe(self.phones)
        self.observe(self.phones[:1], now=129)
        self.assertEqual(len(self.events), 1)
        self.observe(self.phones[:1], now=130)
        self.assertEqual(self.events[-1]["title"], "1 phone still looks unavailable")
        self.observe([], now=140)
        self.observe([], now=154.99)
        self.assertEqual(len(self.events), 2)
        self.observe([], now=155)
        self.assertEqual(self.events[-1]["body"],
                         "All 3 affected phones are reachable again.")
        self.assertEqual(self.events[-1]["category"], "activity")
        self.assertEqual(len({event["notificationTag"] for event in self.events}), 1)
        self.assertEqual(len({event["id"] for event in self.events}), 3)

    def test_brief_outage_suppresses_unnotified_recovery(self):
        recovery = {
            "id": "sig_phone_recovered", "kind": "pbx_phone_recovered_activity",
            "state": "active", "category": "activity", "title": "Phone recovered",
        }
        self.observe(self.phones[:1])
        self.observe([recovery], now=105)
        self.observe([recovery], now=119.99)
        self.assertEqual(self.events, [])
        self.observe([recovery], now=120)
        self.assertEqual(len(self.events), 1)

    def test_connector_failure_freezes_incident_and_endpoint_dedupe(self):
        self.observe(self.phones)
        previous = copy.deepcopy(self.state)
        self.observe([], now=130, connected=False)
        self.assertEqual(self.state, previous)
        self.observe(self.phones, now=140)
        self.assertEqual(len(self.events), 1)
        self.state = {}
        self.events.clear()
        self.observe(self.phones[:1], total=0)
        self.observe([], now=200, total=0, connected=False)
        self.observe(self.phones[:1], now=201, total=0)
        self.assertEqual(len(self.events), 1)

    def test_active_episode_token_change_dedupes_but_new_outage_emits(self):
        self.observe([{**self.phones[0], "notificationId": "episode-one"}], total=0)
        self.observe([{**self.phones[0], "notificationId": "restart-token"}], total=0)
        self.assertEqual(len(self.events), 1)
        self.observe([], now=110, total=0)
        self.observe([{**self.phones[0], "notificationId": "episode-two"}],
                     now=120, total=0)
        self.assertEqual([event["id"] for event in self.events],
                         ["episode-one", "episode-two"])

    def test_cooldown_reoutage_continues_episode_then_expires(self):
        self.observe(self.phones)
        episode = self.state["endpoint_incident"]["episode"]
        self.observe([], now=110)
        self.observe([], now=125)
        self.observe(self.phones, now=130)
        self.assertEqual(self.state["endpoint_incident"]["episode"], episode)
        self.assertEqual(self.events[-1]["id"], f"endpoint_incident_{episode}_3")
        self.observe([], now=140)
        self.observe([], now=155)
        self.observe([], now=275)
        self.assertNotIn("endpoint_incident", self.state)

    def test_eligibility_excludes_tips_quiet_insights_and_live_calls(self):
        base = {"state": "active", "title": "Signal"}
        self.observe([
            {**base, "id": "tip", "category": "recommendation", "importance": "important"},
            {**base, "id": "quiet", "category": "insight", "importance": "feed"},
            {**base, "id": "call", "category": "activity", "kind": "call_active"},
            {**base, "id": "resolved", "state": "resolved", "category": "activity"},
            {**base, "id": "security", "category": "security", "importance": "important"},
            {**base, "id": "activity", "category": "activity", "importance": "feed"},
        ])
        self.assertEqual([event["signalId"] for event in self.events],
                         ["security", "activity"])

    def test_emission_stays_at_original_state_transition(self):
        observations = []
        policy = RelayNotificationPolicy(
            self.state,
            lambda event: observations.append((event, copy.deepcopy(self.state))),
        )
        policy.observe(self.phones, now=100, total_phones=3)
        event, state_at_emit = observations[0]
        self.assertEqual(state_at_emit["endpoint_incident"]["revision"], 1)
        self.assertEqual(state_at_emit["endpoint_incident"]["last_notification_at"], 0)
        self.assertEqual(self.state["endpoint_incident"]["last_notification_at"], 100)
        self.assertEqual(event["signalId"], "sig_endpoint_availability_incident")
