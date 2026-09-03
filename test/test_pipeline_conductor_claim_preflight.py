"""Claim preflight — the conductor's deterministic claim predicate.

Every verdict branch gets a test, and each of those tests also asserts that the
single-question predicate this script replaces would have said CLAIM on the same
item. That second assertion is the point: the three real failures behind the
script (a merged PR an ``--state open`` query cannot see, an open PR the one
field read came back empty for, a claim written in prose) are all shaped the
same way, so a test that only checks the new answer would not notice the script
regressing back into the old blind spot.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from skill_script_helpers import load_skill_script

SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "kiro_crew"
    / "builtin_skills"
    / "pipeline-conductor"
    / "scripts"
    / "claim_preflight.py"
)

REPO = "kirodotdev/KiroCrew"
ITEM = 8029


@pytest.fixture
def mod():
    return load_skill_script("claim_preflight", SCRIPT)


def naive_claim(checks: dict) -> bool:
    """The predicate this script replaces: ONE question, and an empty answer
    read as permission.

    The old skill line was `gh pr list --search ... --state open`, so it could
    see exactly one thing: a same-repo OPEN pull request. It could not see a
    merged PR (wrong state), a fork PR (the search missed them, and the single
    field it fell back on measured empty), a claim written in prose, or a symbol
    that is not on the base.

    Every branch test asserts this returns True, i.e. the old predicate would
    have burned a dispatch on the item.
    """
    hits = checks.get("open_prs")
    if not isinstance(hits, list):
        return True
    return not [hit for hit in hits if isinstance(hit, dict) and not hit.get("is_cross_repository")]


# --------------------------------------------------------------------------- #
# fixtures for fabricated checks
# --------------------------------------------------------------------------- #


def clean_checks(**overrides) -> dict:
    checks = {
        "open_prs": [],
        "merged_prs": [],
        "prose_claim": {
            "closure_requested": False,
            "claimed_by_other": False,
            "claimed_by": None,
            "where": None,
            "comment_id": None,
            "pattern": None,
        },
        "symbol_on_base": {
            "symbols": [],
            "present": [],
            "missing": [],
            "bug_class": False,
            "bug_class_by": None,
        },
        "recency": {"age_days": 200, "author_association": "NONE", "risk": "low"},
    }
    checks.update(overrides)
    return checks


class TestVerdictPrecedence:
    """One test per precedence branch, on fabricated checks — no forge, no git."""

    def test_merged_pr_that_landed_is_already_fixed(self, mod):
        checks = clean_checks(
            merged_prs=[
                {
                    "number": 7900,
                    "author": "somebody",
                    "is_cross_repository": False,
                    "state": "closed",
                    "merge_commit_sha": "abc1234def567890",
                    "landed": True,
                }
            ]
        )
        assert naive_claim(checks) is True  # the old predicate would dispatch
        name, reason, evidence = mod.verdict(checks)
        assert (name, reason) == ("CLOSE", "already-fixed")
        assert evidence == {"pr": 7900, "sha": "abc1234def", "landed": True}
        assert mod.EXIT_CODES[name] == 11
        assert (
            mod.human_line(ITEM, name, reason, evidence, "low")
            == f"CLOSE {ITEM} merged-pr=#7900 sha=abc1234def landed=true"
        )

    def test_merged_pr_that_did_not_land_is_not_coverage(self, mod):
        """A PR merged into somewhere other than the base is not coverage.

        This is the branch that keeps the check honest in the other direction:
        ``merged`` alone must not park a workable item.
        """
        checks = clean_checks(
            merged_prs=[
                {
                    "number": 7901,
                    "author": "somebody",
                    "is_cross_repository": False,
                    "state": "closed",
                    "merge_commit_sha": "deadbeefcafe",
                    "landed": False,
                }
            ]
        )
        name, reason, evidence = mod.verdict(checks)
        assert (name, reason) == ("CLAIM", "clean")
        assert evidence == {"risk": "low"}
        assert mod.EXIT_CODES[name] == 0

    def test_open_fork_pr_skips(self, mod):
        checks = clean_checks(
            open_prs=[
                {
                    "number": 8100,
                    "author": "someone",
                    "is_cross_repository": True,
                    "state": "open",
                    "draft": False,
                }
            ]
        )
        assert naive_claim(checks) is True
        name, reason, evidence = mod.verdict(checks)
        assert (name, reason) == ("SKIP", "open-pr")
        assert evidence == {"pr": 8100, "fork": True, "author": "someone"}
        assert mod.EXIT_CODES[name] == 10
        assert (
            mod.human_line(ITEM, name, reason, evidence, "low")
            == f"SKIP {ITEM} open-pr=#8100 fork=true author=someone"
        )

    def test_landed_merged_pr_outranks_an_open_one(self, mod):
        """Precedence 1 before 2: already-fixed is triage debt, not a skip."""
        checks = clean_checks(
            merged_prs=[{"number": 7900, "merge_commit_sha": "aaaabbbbcccc", "landed": True}],
            open_prs=[{"number": 8100, "author": "x", "is_cross_repository": False}],
        )
        assert mod.verdict(checks)[:2] == ("CLOSE", "already-fixed")

    def test_prose_self_claim_by_another_user_skips(self, mod):
        checks = clean_checks(
            prose_claim={
                "closure_requested": False,
                "claimed_by_other": True,
                "claimed_by": "otherdev",
                "claimed_by_where": "body",
                "where": "body",
                "comment_id": None,
                "pattern": SELF_CLAIM_SAMPLE_PATTERN,
            }
        )
        assert naive_claim(checks) is True
        name, reason, evidence = mod.verdict(checks)
        assert (name, reason) == ("SKIP", "prose-claim")
        assert evidence == {"claimed_by": "otherdev", "where": "body"}
        assert mod.EXIT_CODES[name] == 10
        assert "prose-claim claimed-by=otherdev where=body" in mod.human_line(
            ITEM, name, reason, evidence, "low"
        )

    def test_closure_request_outranks_a_prose_claim(self, mod):
        """Precedence 3 before 4: if the reporter says it is done, it is triage
        debt even when somebody also said they were working on it."""
        checks = clean_checks(
            prose_claim={
                "closure_requested": True,
                "claimed_by_other": True,
                "claimed_by": "otherdev",
                "where": "comment",
                "comment_id": 123456,
                "pattern": "x",
            }
        )
        assert naive_claim(checks) is True
        name, reason, evidence = mod.verdict(checks)
        assert (name, reason) == ("CLOSE", "reporter-asked-close")
        assert evidence == {"comment_id": 123456, "where": "comment"}
        assert mod.EXIT_CODES[name] == 11
        assert (
            mod.human_line(ITEM, name, reason, evidence, "low")
            == f"CLOSE {ITEM} reporter-asked-close comment-id=123456"
        )

    def test_closure_request_in_the_body_reports_where_instead_of_an_id(self, mod):
        evidence = {"comment_id": None, "where": "body"}
        assert (
            mod.human_line(ITEM, "CLOSE", "reporter-asked-close", evidence, "low")
            == f"CLOSE {ITEM} reporter-asked-close where=body"
        )

    def test_absent_symbol_skips_only_for_a_corroborated_bug_item(self, mod):
        checks = clean_checks(
            symbol_on_base={
                "symbols": ["_merge_notifications", "run_probe"],
                "present": ["run_probe"],
                "missing": ["_merge_notifications"],
                "bug_class": True,
                "bug_class_by": "label:bug",
            }
        )
        assert naive_claim(checks) is True
        name, reason, evidence = mod.verdict(checks)
        assert (name, reason) == ("SKIP", "symbol-absent")
        assert evidence == {
            "symbol": "_merge_notifications",
            "missing": ["_merge_notifications"],
            "bug_class_by": "label:bug",
        }
        assert mod.EXIT_CODES[name] == 10
        assert (
            mod.human_line(ITEM, name, reason, evidence, "low")
            == f"SKIP {ITEM} symbol-absent=_merge_notifications"
        )

    def test_an_absent_symbol_on_an_uncorroborated_item_claims_at_high_risk(self, mod):
        """The feature-request case that the unconditional veto parked forever.

        An item proposing to ADD `_merge_notifications` names a symbol that is
        absent by definition, so it would be absent on this pass and every pass
        after it. It must be dispatched, and flagged, not parked.
        """
        checks = clean_checks(
            symbol_on_base={
                "symbols": ["_merge_notifications"],
                "present": [],
                "missing": ["_merge_notifications"],
                "bug_class": False,
                "bug_class_by": None,
            }
        )
        name, reason, evidence = mod.verdict(checks)
        assert (name, reason) == ("CLAIM", "clean")
        assert mod.EXIT_CODES[name] == 0
        assert evidence["risk"] == "high"
        assert evidence["symbol_absent_uncorroborated"] == ["_merge_notifications"]
        # The human line stays one field wide, so the reason rides in --json.
        assert mod.human_line(ITEM, name, reason, evidence, "high") == f"CLAIM {ITEM} risk=high"

    def test_an_uncorroborated_absent_symbol_forces_high_risk(self, mod):
        """Even a stale item from a stranger, which recency alone calls low."""
        checks = clean_checks(
            symbol_on_base={
                "symbols": ["Thing_One"],
                "present": [],
                "missing": ["Thing_One"],
                "bug_class": False,
            },
            recency={"age_days": 900, "author_association": "NONE", "risk": "low"},
        )
        assert mod.risk_of(checks) == "high"
        assert mod.uncorroborated_absent_symbols(checks) == ["Thing_One"]

    def test_a_present_symbol_leaves_risk_alone(self, mod):
        checks = clean_checks(
            symbol_on_base={
                "symbols": ["run_probe"],
                "present": ["run_probe"],
                "missing": [],
                "bug_class": False,
            }
        )
        assert mod.uncorroborated_absent_symbols(checks) == []
        assert mod.risk_of(checks) == "low"

    def test_uncorroborated_absent_symbols_ignores_an_errored_check(self, mod):
        checks = clean_checks(symbol_on_base={"error": "grep-failed", "bug_class": False})
        assert mod.uncorroborated_absent_symbols(checks) == []

    @pytest.mark.parametrize(
        "name",
        ["open_prs", "merged_prs", "prose_claim", "symbol_on_base", "recency"],
    )
    def test_any_errored_check_is_unknown_never_claim(self, mod, name):
        checks = clean_checks(**{name: {"error": "rate-limited"}})
        assert naive_claim(checks) is True
        got, reason, evidence = mod.verdict(checks)
        assert got == "UNKNOWN"
        assert reason == "rate-limited"
        assert evidence == {"check": name, "reason": "rate-limited"}
        assert mod.EXIT_CODES[got] == 3
        assert (
            mod.human_line(ITEM, got, reason, evidence, "high")
            == f"UNKNOWN {ITEM} check={name} reason=rate-limited"
        )

    def test_a_definite_finding_outranks_an_errored_check(self, mod):
        """Precedence 6 sits BELOW the positive findings: a partial view of one
        question does not erase a definite answer to another."""
        checks = clean_checks(
            open_prs=[{"number": 8100, "author": "x", "is_cross_repository": False}],
            recency={"error": "rate-limited"},
        )
        assert mod.verdict(checks)[:2] == ("SKIP", "open-pr")

    def test_clean_item_claims_and_carries_its_risk(self, mod):
        checks = clean_checks(
            recency={"age_days": 1, "author_association": "CONTRIBUTOR", "risk": "high"}
        )
        name, reason, evidence = mod.verdict(checks)
        assert (name, reason) == ("CLAIM", "clean")
        assert evidence == {"risk": "high"}
        assert mod.risk_of(checks) == "high"
        assert mod.EXIT_CODES[name] == 0
        assert mod.human_line(ITEM, name, reason, evidence, "high") == f"CLAIM {ITEM} risk=high"

    def test_the_unreliable_field_is_not_a_check_at_all(self, mod):
        """`closedByPullRequestsReferences` measured `[]` on two items that WERE
        closed by merged PRs, so it is dropped rather than carried as a bonus: a
        per-candidate forge call that cannot change the verdict is pure cost
        against a shared rate limit. Five checks, and none of them is that one.
        """
        assert mod.CHECK_NAMES == (
            "open_prs",
            "merged_prs",
            "prose_claim",
            "symbol_on_base",
            "recency",
        )
        source = SCRIPT.read_text(encoding="utf-8")
        assert "closed_by" not in source
        # The field survives in the rationale only, as the question this script
        # refuses to ask -- never as a call.
        assert "closedByPullRequestsReferences" in source
        assert 'gh_json(\n        [\n            "gh",\n            "issue",' not in source

    def test_no_file_claims_a_check_count_the_code_does_not_have(self, mod):
        """A ratchet, because this exact leftover shipped once.

        Removing one of the checks left the OLD count behind in a docstring and
        in a test name, which a premise-level reviewer correctly reads as the
        description contradicting the diff. Counting words are cheap to forget
        and cheap to pin, so pin them: no line of the script or of this file may
        name a check count other than the real one.

        (This docstring deliberately does not spell any wrong count, since the
        scan reads its own file too.)
        """
        wrong = {"six": 6, "four": 4, "seven": 7}
        for path in (SCRIPT, Path(__file__).resolve()):
            text = path.read_text(encoding="utf-8")
            for word, count in wrong.items():
                if count == len(mod.CHECK_NAMES):
                    continue
                for line in text.splitlines():
                    lowered = line.lower()
                    if word in lowered and "check" in lowered:
                        raise AssertionError(f"{path.name}: stale check count -- {line.strip()!r}")

    def test_risk_defaults_to_high_when_recency_is_unavailable(self, mod):
        assert mod.risk_of(clean_checks(recency={"error": "rate-limited"})) == "high"
        assert mod.risk_of(clean_checks(recency="nonsense")) == "high"

    def test_entries_and_errored_tolerate_the_error_shape(self, mod):
        assert mod.entries({"error": "x"}) == []
        assert mod.entries([{"a": 1}, "junk"]) == [{"a": 1}]
        assert mod.errored({"error": "x"}) == "x"
        assert mod.errored({}) is None
        assert mod.errored([]) is None


SELF_CLAIM_SAMPLE_PATTERN = r"\bI(?:'m| am)\s+claiming\b"


# --------------------------------------------------------------------------- #
# the prose scanner
# --------------------------------------------------------------------------- #


def an_issue(**overrides) -> dict:
    issue = {
        "number": ITEM,
        "title": "the probe cannot tell a finished worker from a wedged one",
        "body": "The handled set keeps one entry per key.",
        "user": {"login": "reporter"},
        "created_at": "2026-01-01T00:00:00Z",
        "author_association": "NONE",
        "labels": [],
        "type": None,
    }
    issue.update(overrides)
    return issue


def a_comment(
    body: str,
    *,
    login="reporter",
    ident=123456,
    kind="User",
    created="2026-09-02T00:00:00Z",
    association=None,
) -> dict:
    """A comment payload. ``association`` defaults to OWNER only so the many
    tests that just need SOME closure request keep standing; the standing rule
    itself is pinned by its own tests, which pass it explicitly.
    """
    return {
        "id": ident,
        "body": body,
        "user": {"login": login, "type": kind},
        "created_at": created,
        "author_association": "OWNER" if association is None else association,
    }


class TestProseScan:
    def test_self_claim_in_the_body_by_another_user(self, mod):
        issue = an_issue(
            body="I'm claiming this issue, patch coming today.", user={"login": "otherdev"}
        )
        prose = mod.scan_prose(issue, None, "us")
        assert prose["claimed_by_other"] is True
        assert prose["claimed_by"] == "otherdev"
        assert prose["claimed_by_where"] == "body"
        assert prose["closure_requested"] is False
        # The PATTERN is reported, never the user's sentence: this lands in an
        # agent's context.
        assert prose["pattern"] in mod.SELF_CLAIM_RES
        assert "claiming this issue" not in json.dumps(prose)

    def test_our_own_self_claim_is_not_somebody_elses(self, mod):
        issue = an_issue(body="I am claiming this one.", user={"login": "us"})
        assert mod.scan_prose(issue, None, "us")["claimed_by_other"] is False

    def test_an_unknown_identity_reads_a_self_claim_as_somebody_elses(self, mod):
        """Fail-safe direction: not knowing who we are must produce SKIP, not
        CLAIM."""
        issue = an_issue(body="I am claiming this one.", user={"login": "us"})
        assert mod.scan_prose(issue, None, None)["claimed_by_other"] is True

    @pytest.mark.parametrize(
        "text",
        [
            "This is resolved, thanks!",
            "happy to have it closed",
            "Please close this one.",
            "this can be closed",
            "no longer reproducible on main",
        ],
    )
    def test_closure_requests_in_the_last_comment(self, mod, text):
        prose = mod.scan_prose(an_issue(), a_comment(text), "us")
        assert prose["closure_requested"] is True
        assert prose["where"] == "comment"
        assert prose["comment_id"] == 123456

    def test_a_comment_outranks_the_body_as_evidence(self, mod):
        prose = mod.scan_prose(an_issue(body="this is resolved"), a_comment("please close"), "us")
        assert prose["where"] == "comment"
        assert prose["comment_id"] == 123456

    def test_ordinary_prose_claims_nothing(self, mod):
        prose = mod.scan_prose(an_issue(), a_comment("Reproduced on 0.6.0, logs attached."), "us")
        assert prose["closure_requested"] is False
        assert prose["claimed_by_other"] is False

    def test_a_quoted_phrase_is_a_citation_not_a_request(self, mod):
        """The regression that found this: the item SPECIFYING this script quotes
        the closure phrases as a description of what to detect, and a raw scan
        returned CLOSE on a live item. Verbatim from that body — including the
        LINE BREAK inside the quotation, which markdown's hard wrap put there and
        which the first version of the stripper walked straight past.
        """
        body = (
            "- A claim written in **prose** -- an assignee in the body, "
            '"this is\n  resolved, please close" in the last comment -- is '
            "invisible to every label and field query.\n"
            'Scan the body and the last comment for "this is resolved / happy '
            'to have it closed".'
        )
        prose = mod.scan_prose(an_issue(body=body), None, "us")
        assert prose["closure_requested"] is False

    @pytest.mark.parametrize(
        "body",
        [
            "```\nplease close\n```",
            "~~~\nthis is resolved\n~~~",
            "the phrase `please close` fires the check",
            "> this is resolved\n\nbut it is not",
            'they said "please close" and I disagree',
            "they said \u201cplease close\u201d and I disagree",
        ],
    )
    def test_cited_closure_phrases_do_not_request_closure(self, mod, body):
        assert mod.scan_prose(an_issue(body=body), None, "us")["closure_requested"] is False

    @pytest.mark.parametrize(
        "body",
        [
            "This is resolved, thanks for the quick turnaround.",
            "Please close this one.",
            "> irrelevant quoted line\n\nthis was fixed in the 0.7 release",
        ],
    )
    def test_an_unquoted_closure_request_still_fires(self, mod, body):
        """The stripper must not swallow the sentence the check exists to find."""
        assert mod.scan_prose(an_issue(body=body), None, "us")["closure_requested"] is True

    def test_a_cited_self_claim_is_not_a_claim(self, mod):
        body = 'three items said "I am claiming this issue" in prose'
        assert mod.scan_prose(an_issue(body=body), None, "us")["claimed_by_other"] is False

    def test_plain_prose_keeps_unquoted_text(self, mod):
        assert "kept" in mod.plain_prose("kept `dropped` kept")
        assert "dropped" not in mod.plain_prose("kept `dropped` kept")
        assert mod.plain_prose("") == ""

    def test_the_newest_human_comment_is_used_not_the_bot_summary(self, mod):
        """Selection is by timestamp, not position, and bots are skipped.

        Both halves are measured, not assumed. The per-issue comments endpoint
        IGNORES `sort`/`direction` and answers OLDEST-first, so an earlier
        version of this function that asked for `direction=desc` and took the
        first element read the oldest of twelve comments; and this repo's triage
        bot summary was the OLDEST entry, not the newest. The timestamps below
        are that real thread's first and last.
        """
        oldest_first = [
            a_comment(
                "**Automated triage summary**",
                login="github-actions[bot]",
                kind="Bot",
                created="2026-09-01T10:40:23Z",
            ),
            a_comment("reproduced on 0.6.0", ident=111, created="2026-09-01T11:19:53Z"),
            a_comment("some-app[bot] body", login="some-app[bot]", created="2026-09-02T04:22:10Z"),
            a_comment(
                "please close, I fixed this myself", ident=999, created="2026-09-03T00:56:58Z"
            ),
        ]
        found = mod.last_human_comment(oldest_first)
        assert found is not None and found["id"] == 999

    def test_selection_survives_either_page_order(self, mod):
        """The bug this replaces was an ordering ASSUMPTION. Reversing the input
        must not change the answer -- that is what makes the fix a fix rather
        than the opposite assumption.
        """
        page = [
            a_comment("older", ident=111, created="2026-09-01T11:19:53Z"),
            a_comment("newer", ident=999, created="2026-09-03T00:56:58Z"),
        ]
        assert mod.last_human_comment(page)["id"] == 999
        assert mod.last_human_comment(list(reversed(page)))["id"] == 999

    def test_position_breaks_ties_only_when_a_timestamp_is_missing(self, mod):
        undated = [
            a_comment("first", ident=1, created=None),
            a_comment("last", ident=2, created=None),
        ]
        assert mod.last_human_comment(undated)["id"] == 2
        mixed = [
            a_comment("dated", ident=1, created="2026-09-01T00:00:00Z"),
            a_comment("undated", ident=2, created=None),
        ]
        assert mod.last_human_comment(mixed)["id"] == 1

    def test_last_human_comment_degrades_on_junk(self, mod):
        assert mod.last_human_comment([]) is None
        assert mod.last_human_comment("nonsense") is None
        assert mod.last_human_comment([{"user": {"type": "Bot"}}]) is None
        assert mod.last_human_comment(["junk"]) is None
        # A deleted account leaves ``user: null``. That is not a bot, and the
        # sentence it left behind still counts.
        orphaned = mod.last_human_comment([{"id": 5, "user": None}])
        assert orphaned is not None and orphaned["id"] == 5

    def test_a_closure_request_needs_standing(self, mod):
        """CLOSE acts on live work, so "please close" from a passer-by is not
        enough. The reporter and a repository insider both have standing."""
        issue = an_issue(user={"login": "reporter"})
        reporter = a_comment("please close", login="reporter", association="NONE")
        assert mod.scan_prose(issue, reporter, "us")["closure_requested"] is True

        maintainer = a_comment("this was fixed in 0.7", login="boss", association="MEMBER")
        got = mod.scan_prose(issue, maintainer, "us")
        assert got["closure_requested"] is True
        assert got["closure_by"] == "boss"

        passerby = a_comment("please close", login="stranger", association="NONE")
        assert mod.scan_prose(issue, passerby, "us")["closure_requested"] is False

    def test_contributor_association_alone_is_not_standing_to_close(self, mod):
        """CONTRIBUTOR only means "has had a PR merged here once", which is not
        authority over another person's report."""
        drive_by = a_comment("please close", login="stranger", association="CONTRIBUTOR")
        got = mod.scan_prose(an_issue(user={"login": "reporter"}), drive_by, "us")
        assert got["closure_requested"] is False

    def test_a_self_claim_needs_no_standing(self, mod):
        """Standing gates CLOSE, not SKIP: anyone announcing they are on it is
        a reason to stay away, and SKIP is the cheap direction."""
        stranger = a_comment("I am claiming this one", login="stranger", association="NONE")
        got = mod.scan_prose(an_issue(user={"login": "reporter"}), stranger, "us")
        assert got["claimed_by_other"] is True
        assert got["claimed_by"] == "stranger"


class TestBugClassCorroboration:
    """Explicit metadata only. A label is a human's deliberate triage act, which
    is what makes it corroboration; wording is not."""

    @pytest.mark.parametrize(
        "label,term",
        [
            ("bug", "bug"),
            ("Bug", "bug"),
            ("type: bug", "bug"),
            ("kind/bug", "bug"),
            ("defect", "defect"),
            ("regression", "regression"),
            ("crash", "crash"),
        ],
    )
    def test_a_bug_label_corroborates(self, mod, label, term):
        got, by = mod.bug_class_of(an_issue(labels=[{"name": label}]))
        assert got is True
        # The MATCHED TERM, from this module's own vocabulary -- never the
        # label's text, which is user-authored and this value is printed.
        assert by == f"label:{term}"

    def test_the_corroboration_never_echoes_the_label_text(self, mod):
        """The script's own contract is that nothing user-authored reaches
        stdout. A label name is user-authored, so only the matched term rides."""
        noisy = "type: Bug -- customer ACME, see ticket 4471 (bob@example.invalid)"
        got, by = mod.bug_class_of(an_issue(labels=[{"name": noisy}]))
        assert (got, by) == (True, "label:bug")
        for leaked in ("ACME", "4471", "bob@example.invalid", noisy):
            assert leaked not in str(by)

    @pytest.mark.parametrize(
        "label",
        ["enhancement", "feature request", "documentation", "good first issue", "debugging"],
    )
    def test_a_non_bug_label_does_not_corroborate(self, mod, label):
        assert mod.bug_class_of(an_issue(labels=[{"name": label}])) == (False, None)

    def test_an_issue_type_corroborates(self, mod):
        got, by = mod.bug_class_of(an_issue(type={"name": "Bug"}))
        assert (got, by) == (True, "type:bug")

    def test_a_feature_type_does_not(self, mod):
        assert mod.bug_class_of(an_issue(type={"name": "Feature"})) == (False, None)

    def test_no_metadata_does_not_corroborate(self, mod):
        """An untriaged item is not corroborated, and that is the CHEAP
        direction: it is dispatched with risk=high, not parked."""
        assert mod.bug_class_of(an_issue()) == (False, None)

    def test_junk_metadata_degrades_quietly(self, mod):
        assert mod.bug_class_of(an_issue(labels="nonsense")) == (False, None)
        assert mod.bug_class_of(an_issue(labels=[None, 7, {"no": "name"}])) == (False, None)
        assert mod.bug_class_of(an_issue(type="nonsense")) == (False, None)
        assert mod.bug_class_of(an_issue(labels=["bug"])) == (True, "label:bug")

    def test_the_corroboration_rides_on_the_check_value(self, mod):
        got = mod.symbols_on_base([], None, "main", bug_class=True, bug_class_by="label:bug")
        assert got["bug_class"] is True
        assert got["bug_class_by"] == "label:bug"
        # Also present on the error shapes, so the verdict never reads a missing
        # key as "not a bug".
        assert mod.symbols_on_base(["X_Y"], None, "main", bug_class=True)["bug_class"] is True


class TestSymbolExtraction:
    @pytest.mark.parametrize(
        "token,expected",
        [
            ("_merge_notifications", True),
            ("PER_FILE_MIN", True),
            ("runProbe", True),
            ("main", False),
            ("true", False),
            ("PR", False),
        ],
    )
    def test_looks_like_symbol(self, mod, token, expected):
        assert mod.looks_like_symbol(token) is expected

    def test_named_symbols_takes_backticked_identifiers_in_order(self, mod):
        text = (
            "`_merge_notifications()` is gone, so `runProbe` and `main` and `_merge_notifications`"
        )
        assert mod.named_symbols(text) == ["_merge_notifications", "runProbe"]

    def test_named_symbols_is_capped(self, mod):
        text = " ".join(f"`sym_{index}`" for index in range(20))
        assert len(mod.named_symbols(text, limit=3)) == 3
        assert mod.named_symbols("") == []


class TestRecency:
    def test_fresh_item_from_an_active_contributor_is_high_risk(self, mod):
        now = datetime(2026, 9, 3, tzinfo=timezone.utc)
        issue = an_issue(
            created_at=(now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            author_association="CONTRIBUTOR",
        )
        got = mod.scan_recency(issue, now=now)
        assert got == {"age_days": 1, "author_association": "CONTRIBUTOR", "risk": "high"}

    def test_old_item_from_an_active_contributor_is_low_risk(self, mod):
        now = datetime(2026, 9, 3, tzinfo=timezone.utc)
        issue = an_issue(created_at="2026-01-01T00:00:00Z", author_association="MEMBER")
        assert mod.scan_recency(issue, now=now)["risk"] == "low"

    def test_fresh_item_from_a_stranger_is_low_risk(self, mod):
        now = datetime(2026, 9, 3, tzinfo=timezone.utc)
        issue = an_issue(
            created_at=(now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            author_association="NONE",
        )
        assert mod.scan_recency(issue, now=now)["risk"] == "low"

    def test_an_unparseable_timestamp_does_not_certify_low_risk(self, mod):
        assert mod.scan_recency(an_issue(created_at="not a date"))["risk"] == "high"
        assert mod.scan_recency(an_issue(created_at=None))["age_days"] is None

    def test_a_naive_timestamp_is_read_as_utc(self, mod):
        now = datetime(2026, 9, 3, tzinfo=timezone.utc)
        assert (
            mod.scan_recency(an_issue(created_at="2026-09-01T00:00:00"), now=now)["age_days"] == 2
        )


# --------------------------------------------------------------------------- #
# the read-only guard — the no-write property, enforced not promised
# --------------------------------------------------------------------------- #


class TestNoWrites:
    @pytest.mark.parametrize(
        "argv",
        [
            ["gh", "api", "repos/o/r/issues/1"],
            ["gh", "api", "repos/o/r/issues/1/timeline", "--paginate"],
            ["gh", "issue", "view", "1", "--repo", "o/r", "--json", "number"],
            ["gh", "api", "user"],
            ["gh", "api", "repos/o/r/pulls/2", "-X", "GET"],
        ],
    )
    def test_reads_are_allowed(self, mod, argv):
        assert mod.is_read_only(argv) is True

    @pytest.mark.parametrize(
        "argv",
        [
            ["gh", "issue", "close", "1"],
            ["gh", "issue", "edit", "1", "--add-label", "claimed"],
            ["gh", "issue", "comment", "1", "--body", "mine"],
            ["gh", "pr", "merge", "2"],
            ["gh", "api", "repos/o/r/issues/1/labels", "-X", "POST"],
            ["gh", "api", "repos/o/r/issues/1", "--method", "PATCH"],
            ["gh", "api", "repos/o/r/issues/1", "--method=DELETE"],
            ["gh", "api", "repos/o/r/issues/1/labels", "-f", "labels[]=claimed"],
            ["gh", "api", "repos/o/r/issues/1", "--field", "state=closed"],
            ["curl", "https://api.github.com"],
            ["gh"],
        ],
    )
    def test_writes_are_refused(self, mod, argv):
        assert mod.is_read_only(argv) is False

    def test_a_refused_argv_never_reaches_a_subprocess(self, mod, monkeypatch):
        monkeypatch.setattr(
            mod, "run", lambda *a, **k: pytest.fail("a refused argv reached subprocess")
        )
        rc, out, err = mod.run_gh(["gh", "issue", "close", "1"])
        assert (rc, out) == (126, "")
        assert "no writes" in err
        assert mod.error_slug(rc, err) == "refused-write"

    def test_the_script_source_contains_no_write_verb(self, mod):
        """A source-level backstop for the guard: a future edit that adds a
        write has to defeat both."""
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "issue close",
            "issue edit",
            "issue comment",
            "pr merge",
            "--add-label",
            "--add-assignee",
            "--remove-label",
        ):
            assert f'"{forbidden}"' not in source
            assert f"'{forbidden}'" not in source

    def test_a_full_run_issues_only_reads(self, mod, monkeypatch):
        forge = Forge()
        monkeypatch.setattr(mod, "run", forge)
        assert mod.main(["--repo", REPO, "--item", str(ITEM)]) == 0
        assert forge.calls, "the run made no calls at all"
        for argv in forge.calls:
            if argv[0] == "gh":
                assert mod.is_read_only(argv), argv
            else:
                # git, and only ever read verbs on a clone we do not own.
                assert argv[:2] == ["git", "-C"]
                assert argv[3] in {"rev-parse", "merge-base", "grep"}, argv


# --------------------------------------------------------------------------- #
# end to end, over a stubbed forge
# --------------------------------------------------------------------------- #


def a_pull(
    number: int,
    *,
    state: str = "open",
    merged: bool = False,
    sha: str | None = None,
    head: str | None = REPO,
    user: str = "someone",
    draft: bool = False,
) -> dict:
    return {
        "number": number,
        "state": state,
        "merged": merged,
        "merge_commit_sha": sha,
        "draft": draft,
        "user": {"login": user},
        "head": {"repo": {"full_name": head} if head else None},
        "base": {"repo": {"full_name": REPO}},
    }


def a_xref(number: int, *, repo: str = REPO) -> dict:
    return {
        "event": "cross-referenced",
        "source": {
            "type": "issue",
            "issue": {
                "number": number,
                "pull_request": {"url": f"https://api.github.com/repos/{repo}/pulls/{number}"},
                "repository": {"full_name": repo},
            },
        },
    }


class Forge:
    """A stand-in for the module's ``run``: routes an argv to canned output.

    Records every call so a test can assert on what the script asked, including
    that it never asked for a write.
    """

    def __init__(
        self,
        *,
        timeline: list | None = None,
        pulls: dict | None = None,
        issue: dict | None = None,
        comments: list | None = None,
        login: str = "us",
        failures: dict | None = None,
        git_rc: dict | None = None,
    ):
        self.timeline = timeline if timeline is not None else []
        self.pulls = pulls or {}
        self.issue = issue if issue is not None else an_issue()
        self.comments = comments if comments is not None else []
        self.login = login
        self.failures = failures or {}
        self.git_rc = git_rc or {}
        self.calls: list[list[str]] = []

    def __call__(self, argv, cwd=None):
        self.calls.append(list(argv))
        if argv[0] == "git":
            # ``rev-parse --git-dir`` is the --repo-dir validation and
            # ``rev-parse --verify`` the default-branch check: two different
            # questions, so a test can fail one without failing the other.
            verb = "git-dir" if "--git-dir" in argv else argv[3]
            return self.git_rc.get(verb, 0), "", ""
        target = argv[2] if len(argv) > 2 else ""
        for needle, slug in self.failures.items():
            if needle in " ".join(argv):
                return 1, "", slug
        if "/timeline" in target:
            return 0, json.dumps(self.timeline), ""
        if "/pulls/" in target:
            number = int(target.rsplit("/", 1)[1])
            return 0, json.dumps(self.pulls[number]), ""
        if "/comments" in target:
            return 0, json.dumps(self.comments), ""
        if target == "user":
            return 0, json.dumps({"login": self.login}), ""
        if target.startswith("repos/") and "/issues/" in target:
            return 0, json.dumps(self.issue), ""
        raise AssertionError(f"unrouted argv: {argv}")  # pragma: no cover


def run_main(mod, monkeypatch, forge: Forge, extra: list[str] | None = None) -> int:
    monkeypatch.setattr(mod, "run", forge)
    return mod.main(["--repo", REPO, "--item", str(ITEM), *(extra or [])])


class TestEndToEnd:
    def test_clean_item_exits_zero_and_prints_the_claim_line(self, mod, monkeypatch, capsys):
        fresh = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        forge = Forge(issue=an_issue(created_at=fresh, author_association="CONTRIBUTOR"))
        assert run_main(mod, monkeypatch, forge) == 0
        assert capsys.readouterr().out.strip() == f"CLAIM {ITEM} risk=high"

    def test_a_merged_landed_pr_exits_eleven(self, mod, monkeypatch, capsys):
        forge = Forge(
            timeline=[a_xref(7900)],
            pulls={7900: a_pull(7900, state="closed", merged=True, sha="abc1234def567890")},
            git_rc={"merge-base": 0},
        )
        assert run_main(mod, monkeypatch, forge, ["--repo-dir", "/clone"]) == 11
        assert (
            capsys.readouterr().out.strip()
            == f"CLOSE {ITEM} merged-pr=#7900 sha=abc1234def landed=true"
        )

    def test_a_merged_pr_that_landed_elsewhere_still_claims(self, mod, monkeypatch, capsys):
        forge = Forge(
            timeline=[a_xref(7901)],
            pulls={7901: a_pull(7901, state="closed", merged=True, sha="deadbeefcafe")},
            git_rc={"merge-base": 1},
        )
        assert run_main(mod, monkeypatch, forge, ["--repo-dir", "/clone"]) == 0
        assert capsys.readouterr().out.strip().startswith(f"CLAIM {ITEM}")

    def test_an_open_fork_pr_exits_ten(self, mod, monkeypatch, capsys):
        forge = Forge(
            timeline=[a_xref(8100)],
            pulls={8100: a_pull(8100, head="leozhad/KiroCrew", user="leozhad")},
        )
        assert run_main(mod, monkeypatch, forge) == 10
        assert (
            capsys.readouterr().out.strip() == f"SKIP {ITEM} open-pr=#8100 fork=true author=leozhad"
        )

    def test_a_deleted_head_repo_reads_as_a_fork(self, mod, monkeypatch, capsys):
        forge = Forge(timeline=[a_xref(8101)], pulls={8101: a_pull(8101, head=None)})
        assert run_main(mod, monkeypatch, forge) == 10
        assert "fork=true" in capsys.readouterr().out

    def test_a_closed_unmerged_pr_frees_the_item(self, mod, monkeypatch):
        forge = Forge(
            timeline=[a_xref(8102)], pulls={8102: a_pull(8102, state="closed", merged=False)}
        )
        assert run_main(mod, monkeypatch, forge) == 0

    def test_a_reference_from_another_repository_is_not_coverage(self, mod, monkeypatch):
        forge = Forge(timeline=[a_xref(5, repo="someone/else")], pulls={})
        assert run_main(mod, monkeypatch, forge) == 0

    def test_the_other_timeline_events_are_ignored(self, mod, monkeypatch):
        """A real timeline is mostly not cross-references. Measured on one item
        of this repo: 11 ``commented``, 7 ``labeled``, 2 ``referenced``, 5
        ``cross-referenced`` — and one of those five pointed at an ISSUE, not a
        PR. Every shape but the PR cross-reference must pass through untouched.
        """
        issue_to_issue = a_xref(4242)
        issue_to_issue["source"]["issue"].pop("pull_request")
        forge = Forge(
            timeline=[
                {"event": "commented", "body": "still broken"},
                {"event": "labeled", "label": {"name": "bug"}},
                {"event": "referenced", "commit_id": "abc"},
                issue_to_issue,
                {"event": "cross-referenced", "source": None},
                {"event": "cross-referenced", "source": {"issue": "junk"}},
                "not even a dict",
                a_xref(8100),
                a_xref(8100),  # the same PR twice: one detail call, not two
            ],
            pulls={8100: a_pull(8100, user="someone")},
        )
        assert run_main(mod, monkeypatch, forge) == 10
        detail_calls = [c for c in forge.calls if len(c) > 2 and "/pulls/" in c[2]]
        assert detail_calls == [["gh", "api", f"repos/{REPO}/pulls/8100"]]

    def test_a_failure_detailing_one_pr_is_unknown(self, mod, monkeypatch, capsys):
        """The reference exists but its fork-ness and merge commit are unknown:
        a half-read coverage answer must not read as "no coverage"."""
        forge = Forge(
            timeline=[a_xref(8100)],
            pulls={8100: a_pull(8100)},
            failures={"/pulls/8100": "API rate limit exceeded"},
        )
        assert run_main(mod, monkeypatch, forge) == 3
        assert "check=open_prs reason=rate-limited" in capsys.readouterr().out

    def test_unparseable_pr_detail_is_unknown(self, mod, monkeypatch, capsys):
        forge = Forge(timeline=[a_xref(8100)], pulls={8100: ["not", "an", "object"]})
        assert run_main(mod, monkeypatch, forge) == 3
        assert "reason=unparseable-json" in capsys.readouterr().out

    def test_prose_claim_by_another_user_exits_ten(self, mod, monkeypatch, capsys):
        forge = Forge(
            issue=an_issue(body="Ownership claimed by @otherdev", user={"login": "otherdev"}),
            login="us",
        )
        assert run_main(mod, monkeypatch, forge) == 10
        out = capsys.readouterr().out.strip()
        assert out == f"SKIP {ITEM} prose-claim claimed-by=otherdev where=body"

    def test_reporter_asked_close_in_the_last_comment_exits_eleven(self, mod, monkeypatch, capsys):
        forge = Forge(
            comments=[
                a_comment("automated triage summary", login="github-actions[bot]", kind="Bot"),
                a_comment("happy to have it closed", ident=777),
            ]
        )
        assert run_main(mod, monkeypatch, forge) == 11
        assert (
            capsys.readouterr().out.strip() == f"CLOSE {ITEM} reporter-asked-close comment-id=777"
        )

    def test_an_absent_symbol_on_a_labelled_bug_exits_ten(self, mod, monkeypatch, capsys):
        forge = Forge(
            issue=an_issue(
                body="`_merge_notifications` never fires.",
                labels=[{"name": "bug"}],
            ),
            git_rc={"grep": 1},
        )
        assert run_main(mod, monkeypatch, forge, ["--repo-dir", "/clone"]) == 10
        assert capsys.readouterr().out.strip() == f"SKIP {ITEM} symbol-absent=_merge_notifications"

    def test_an_absent_symbol_on_an_unlabelled_item_claims_at_high_risk(
        self, mod, monkeypatch, capsys
    ):
        """End to end for the item class the unconditional veto parked: nothing
        corroborates bug-class, so it is dispatched and flagged, not parked."""
        forge = Forge(
            issue=an_issue(body="Please add `_merge_notifications` so the digest can batch."),
            git_rc={"grep": 1},
        )
        assert run_main(mod, monkeypatch, forge, ["--repo-dir", "/clone"]) == 0
        assert capsys.readouterr().out.strip() == f"CLAIM {ITEM} risk=high"

    def test_an_issue_type_corroborates_bug_class_too(self, mod, monkeypatch):
        forge = Forge(
            issue=an_issue(
                body="`_merge_notifications` never fires.",
                type={"name": "Bug"},
            ),
            git_rc={"grep": 1},
        )
        assert run_main(mod, monkeypatch, forge, ["--repo-dir", "/clone"]) == 10

    def test_a_present_symbol_claims(self, mod, monkeypatch):
        forge = Forge(issue=an_issue(body="`_merge_notifications` misfires."), git_rc={"grep": 0})
        assert run_main(mod, monkeypatch, forge, ["--repo-dir", "/clone"]) == 0

    def test_a_named_symbol_without_a_clone_is_unknown(self, mod, monkeypatch, capsys):
        """The honest half of ``--repo-dir`` being optional: a question git alone
        can answer, with no git, is UNKNOWN — not a guess in either direction."""
        forge = Forge(issue=an_issue(body="`_merge_notifications` never fires."))
        assert run_main(mod, monkeypatch, forge) == 3
        assert "check=symbol_on_base reason=no-repo-dir" in capsys.readouterr().out

    def test_a_merged_pr_without_a_clone_is_unknown(self, mod, monkeypatch, capsys):
        forge = Forge(
            timeline=[a_xref(7900)],
            pulls={7900: a_pull(7900, state="closed", merged=True, sha="abc1234def")},
        )
        assert run_main(mod, monkeypatch, forge) == 3
        assert "check=merged_prs reason=no-repo-dir" in capsys.readouterr().out

    def test_an_unresolvable_ancestry_is_unknown_not_did_not_land(self, mod, monkeypatch, capsys):
        """A stale clone missing the merge commit must not read as "did not
        land" — that reading is exactly how an already-fixed item was
        dispatched."""
        forge = Forge(
            timeline=[a_xref(7900)],
            pulls={7900: a_pull(7900, state="closed", merged=True, sha="abc1234def")},
            git_rc={"merge-base": 128},
        )
        assert run_main(mod, monkeypatch, forge, ["--repo-dir", "/clone"]) == 3
        assert "reason=ancestry-unknown" in capsys.readouterr().out

    def test_a_merged_pr_with_no_merge_commit_is_unknown(self, mod, monkeypatch, capsys):
        forge = Forge(
            timeline=[a_xref(7900)],
            pulls={7900: a_pull(7900, state="closed", merged=True, sha=None)},
        )
        assert run_main(mod, monkeypatch, forge, ["--repo-dir", "/clone"]) == 3
        assert "reason=no-merge-commit" in capsys.readouterr().out

    def test_an_unknown_default_branch_is_unknown(self, mod, monkeypatch, capsys):
        forge = Forge(
            timeline=[a_xref(7900)],
            pulls={7900: a_pull(7900, state="closed", merged=True, sha="abc1234def")},
            git_rc={"rev-parse": 1},
        )
        assert run_main(mod, monkeypatch, forge, ["--repo-dir", "/clone"]) == 3
        assert "reason=unknown-default-branch" in capsys.readouterr().out

    def test_a_failed_grep_is_unknown_not_an_absent_symbol(self, mod, monkeypatch, capsys):
        forge = Forge(
            issue=an_issue(body="`_merge_notifications` never fires."), git_rc={"grep": 2}
        )
        assert run_main(mod, monkeypatch, forge, ["--repo-dir", "/clone"]) == 3
        assert "reason=grep-failed" in capsys.readouterr().out

    def test_a_rate_limited_timeline_is_unknown(self, mod, monkeypatch, capsys):
        forge = Forge(failures={"/timeline": "API rate limit exceeded"})
        assert run_main(mod, monkeypatch, forge) == 3
        assert (
            capsys.readouterr().out.strip() == f"UNKNOWN {ITEM} check=open_prs reason=rate-limited"
        )

    def test_an_unreachable_issue_endpoint_is_unknown(self, mod, monkeypatch, capsys):
        forge = Forge(failures={f"repos/{REPO}/issues/{ITEM}": "could not resolve host"})
        assert run_main(mod, monkeypatch, forge) == 3
        assert "reason=forge-unreachable" in capsys.readouterr().out

    def test_a_failed_comment_fetch_is_unknown_not_half_an_answer(self, mod, monkeypatch, capsys):
        forge = Forge(failures={"/comments": "server error"})
        assert run_main(mod, monkeypatch, forge) == 3
        assert "check=prose_claim" in capsys.readouterr().out

    def test_the_dropped_check_costs_no_forge_call(self, mod, monkeypatch):
        """The reason it was dropped: a call that cannot change the verdict is
        pure cost against a shared rate limit. Assert the call is not made."""
        forge = Forge()
        assert run_main(mod, monkeypatch, forge) == 0
        for argv in forge.calls:
            assert "closedByPullRequestsReferences" not in " ".join(argv)
            assert argv[:2] != ["gh", "issue"]

    def test_too_many_references_is_unknown(self, mod, monkeypatch, capsys):
        forge = Forge(timeline=[a_xref(n) for n in range(9000, 9000 + mod.MAX_PR_DETAILS + 1)])
        assert run_main(mod, monkeypatch, forge) == 3
        assert "reason=too-many-references" in capsys.readouterr().out

    def test_unparseable_forge_output_is_unknown(self, mod, monkeypatch):
        forge = Forge()

        def broken(argv, cwd=None):
            forge.calls.append(list(argv))
            if "/timeline" in " ".join(argv):
                return 0, "{not json", ""
            return forge(argv, cwd)

        monkeypatch.setattr(mod, "run", broken)
        assert mod.main(["--repo", REPO, "--item", str(ITEM)]) == 3

    def test_json_mode_prints_exactly_one_object(self, mod, monkeypatch, capsys):
        forge = Forge(
            timeline=[a_xref(8100)],
            pulls={8100: a_pull(8100, head="leozhad/KiroCrew", user="leozhad")},
        )
        assert run_main(mod, monkeypatch, forge, ["--json"]) == 10
        out = capsys.readouterr().out
        payload = json.loads(out)  # one object, or this raises
        assert out.strip().count("\n") == 0
        assert payload["item"] == ITEM
        assert payload["verdict"] == "SKIP"
        assert payload["reason"] == "open-pr"
        assert payload["risk"] in {"low", "high"}
        assert set(payload["checks"]) == set(mod.CHECK_NAMES)
        assert payload["evidence"] == {"pr": 8100, "fork": True, "author": "leozhad"}

    def test_json_mode_reports_the_five_checks_even_on_unknown(self, mod, monkeypatch, capsys):
        forge = Forge(failures={"/timeline": "API rate limit exceeded"})
        assert run_main(mod, monkeypatch, forge, ["--json"]) == 3
        payload = json.loads(capsys.readouterr().out)
        assert set(payload["checks"]) == set(mod.CHECK_NAMES)
        assert payload["checks"]["open_prs"] == {"error": "rate-limited"}


class TestArgumentHandling:
    @pytest.mark.parametrize(
        "argv",
        [
            ["--repo", "not-a-repo", "--item", "1"],
            ["--repo", REPO, "--item", "0"],
            ["--repo", REPO, "--item", "-3"],
            ["--repo", REPO, "--item", "1", "--default-branch", "  "],
        ],
    )
    def test_malformed_arguments_exit_two(self, mod, monkeypatch, argv, capsys):
        monkeypatch.setattr(mod, "run", lambda *a, **k: pytest.fail("ran before validating"))
        assert mod.main(argv) == 2
        assert capsys.readouterr().err.strip().startswith("malformed")

    def test_a_repo_dir_that_is_not_a_clone_exits_two(self, mod, monkeypatch, capsys):
        monkeypatch.setattr(mod, "run", lambda argv, cwd=None: (128, "", "not a git repository"))
        assert mod.main(["--repo", REPO, "--item", "1", "--repo-dir", "/nope"]) == 2
        assert "not a git repository" in capsys.readouterr().err

    def test_a_non_numeric_item_is_rejected_by_argparse(self, mod):
        with pytest.raises(SystemExit) as excinfo:
            mod.main(["--repo", REPO, "--item", "eight"])
        assert excinfo.value.code == 2

    def test_exit_codes_are_the_documented_ones(self, mod):
        assert mod.EXIT_CODES == {"CLAIM": 0, "SKIP": 10, "CLOSE": 11, "UNKNOWN": 3}


class TestForgeHelpers:
    def test_run_reports_a_missing_binary_instead_of_raising(self, mod):
        rc, out, err = mod.run(["definitely-not-a-real-binary-9f3a"])
        assert rc == 127
        assert out == ""
        assert mod.error_slug(rc, err) == "gh-missing"

    @pytest.mark.parametrize(
        "rc,err,slug",
        [
            (1, "API rate limit exceeded for user", "rate-limited"),
            (1, "HTTP 429 Too Many Requests", "rate-limited"),
            (1, "gh auth login required", "not-authenticated"),
            (1, "HTTP 404: Not Found", "not-found"),
            (1, "dial tcp: lookup api.github.com", "forge-unreachable"),
            (1, "context deadline exceeded: timed out", "forge-unreachable"),
            (7, "something else entirely", "gh-error-rc7"),
        ],
    )
    def test_error_slugs_never_echo_the_stderr(self, mod, rc, err, slug):
        got = mod.error_slug(rc, err)
        assert got == slug
        assert " " not in got

    def test_gh_json_parses_and_reports(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", lambda argv, cwd=None: (0, '{"a": 1}', ""))
        assert mod.gh_json(["gh", "api", "user"]) == ({"a": 1}, None)
        monkeypatch.setattr(mod, "run", lambda argv, cwd=None: (0, "", ""))
        assert mod.gh_json(["gh", "api", "user"]) == (None, None)
        monkeypatch.setattr(mod, "run", lambda argv, cwd=None: (0, "{", ""))
        assert mod.gh_json(["gh", "api", "user"]) == (None, "unparseable-json")

    def test_pagination_survives_either_output_shape(self, mod):
        """`gh api --paginate` MERGES array pages into one document -- measured on
        gh 2.96.0, a 4-page timeline came back as one array of 33. This pins that
        path AND the concatenated-documents shape, because the script pins no gh
        version and a page boundary must never turn a covered item into UNKNOWN.
        """
        merged = mod.parse_pages('[{"n": 1}, {"n": 2}, {"n": 3}]')
        assert merged == [{"n": 1}, {"n": 2}, {"n": 3}]

        concatenated = mod.parse_pages('[{"n": 1}, {"n": 2}]\n[{"n": 3}]\n')
        assert concatenated == [{"n": 1}, {"n": 2}, {"n": 3}]

        # A single object, and several of them, both survive.
        assert mod.parse_pages('{"login": "us"}') == {"login": "us"}
        assert mod.parse_pages('{"a": 1}\n{"b": 2}') == [{"a": 1}, {"b": 2}]
        assert mod.parse_pages("null") is None

    def test_a_torn_page_is_still_a_failed_answer(self, mod, monkeypatch):
        """Tolerating page boundaries must not tolerate garbage: an unparseable
        payload stays UNKNOWN rather than becoming an empty result."""
        with pytest.raises(ValueError):
            mod.parse_pages('[{"n": 1}] [{"n": 2}')
        monkeypatch.setattr(mod, "run", lambda argv, cwd=None: (0, '[{"n": 1}] [{"n": 2}', ""))
        assert mod.gh_json(["gh", "api", "x"]) == (None, "unparseable-json")

    def test_a_multi_page_timeline_still_finds_its_references(self, mod, monkeypatch):
        """End to end over the concatenated shape: the covering PR is found, so a
        page boundary cannot produce a false CLAIM."""
        pages = json.dumps([a_xref(8100)]) + "\n" + json.dumps([a_xref(8101)])
        forge = Forge(
            pulls={
                8100: a_pull(8100, state="closed", merged=False),
                8101: a_pull(8101, user="someone"),
            }
        )

        def paged(argv, cwd=None):
            forge.calls.append(list(argv))
            if len(argv) > 2 and "/timeline" in argv[2]:
                return 0, pages, ""
            return forge(argv, cwd)

        monkeypatch.setattr(mod, "run", paged)
        assert mod.main(["--repo", REPO, "--item", str(ITEM)]) == 10

    def test_whoami_degrades_to_none(self, mod, monkeypatch):
        monkeypatch.setattr(mod, "run", lambda argv, cwd=None: (0, '{"login": "us"}', ""))
        assert mod.whoami() == "us"
        monkeypatch.setattr(mod, "run", lambda argv, cwd=None: (1, "", "boom"))
        assert mod.whoami() is None
        monkeypatch.setattr(mod, "run", lambda argv, cwd=None: (0, "[]", ""))
        assert mod.whoami() is None


class TestAgainstRealGit:
    """The git flags, over a real repository.

    Everything else stubs ``run``, which cannot catch a wrong flag: a bad
    ``git grep`` invocation returns a non-zero code that the stub would never
    produce, and ``--is-ancestor`` reversed would read every landed merge as
    unlanded. One small real repo pins both.
    """

    @pytest.fixture
    def clone(self, tmp_path):
        root = tmp_path / "clone"
        root.mkdir()

        def run_git(*args):
            rc, out, err = 0, "", ""
            rc, out, err = _git(root, list(args))
            assert rc == 0, f"git {args} failed: {err}"
            return out

        run_git("init", "--initial-branch=main", "-q")
        run_git("config", "user.email", "preflight@example.invalid")
        run_git("config", "user.name", "preflight")
        (root / "landed.py").write_text("def _merge_notifications():\n    pass\n", encoding="utf-8")
        run_git("add", "landed.py")
        run_git("commit", "-q", "-m", "landed")
        on_main = run_git("rev-parse", "HEAD")
        run_git("checkout", "-q", "-b", "sidetrack")
        (root / "elsewhere.py").write_text("SIDE = 1\n", encoding="utf-8")
        run_git("add", "elsewhere.py")
        run_git("commit", "-q", "-m", "elsewhere")
        off_main = run_git("rev-parse", "HEAD")
        run_git("checkout", "-q", "main")
        return root, on_main, off_main

    def test_ancestry_distinguishes_landed_from_elsewhere(self, mod, clone):
        root, on_main, off_main = clone
        merged = [
            {"number": 1, "merge_commit_sha": on_main},
            {"number": 2, "merge_commit_sha": off_main},
        ]
        assert mod.annotate_landed(merged, str(root), "main") is None
        assert merged[0]["landed"] is True
        assert merged[1]["landed"] is False

    def test_a_commit_absent_from_the_clone_is_not_did_not_land(self, mod, clone):
        root, _, _ = clone
        merged = [{"number": 3, "merge_commit_sha": "0" * 40}]
        assert mod.annotate_landed(merged, str(root), "main") == "ancestry-unknown"
        assert "landed" not in merged[0]

    def test_an_unknown_branch_is_reported(self, mod, clone):
        root, on_main, _ = clone
        merged = [{"number": 1, "merge_commit_sha": on_main}]
        assert mod.annotate_landed(merged, str(root), "no-such-branch") == "unknown-default-branch"

    def test_no_merged_prs_needs_no_clone(self, mod):
        assert mod.annotate_landed([], None, "main") is None

    def test_git_grep_finds_a_symbol_on_the_branch_only(self, mod, clone):
        root, _, _ = clone
        got = mod.symbols_on_base(["_merge_notifications", "SIDE"], str(root), "main")
        assert got["present"] == ["_merge_notifications"]
        assert got["missing"] == ["SIDE"]
        assert mod.symbols_on_base(["SIDE"], str(root), "sidetrack")["present"] == ["SIDE"]

    def test_symbols_on_base_needs_no_clone_when_nothing_is_named(self, mod):
        assert mod.symbols_on_base([], None, "main") == {
            "symbols": [],
            "present": [],
            "missing": [],
            "bug_class": False,
            "bug_class_by": None,
        }

    def test_symbols_on_base_reports_an_unknown_branch(self, mod, clone):
        root, _, _ = clone
        got = mod.symbols_on_base(["SIDE"], str(root), "no-such-branch")
        assert got["error"] == "unknown-default-branch"


def _git(root: Path, args: list[str]):
    """Run git against ``root``, contained two ways.

    ``-C root`` already makes git run as if started there, so the operation
    targets the fixture. ``cwd=root`` is belt and braces: it means a future
    call site that forgets ``-C`` still cannot reach the checkout, which is
    what the no-test-side-effects rule is protecting.
    """
    import subprocess

    done = subprocess.run(
        ["git", "-C", str(root), *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return done.returncode, (done.stdout or "").strip(), (done.stderr or "").strip()
