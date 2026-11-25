"""The pure guest clone and fetch plans against the independent expected
outcomes in acquisitions/git/contract/v1/semantics-fixtures.json."""

import json
import os
import unittest

from acquisitions.git.jail.semantics import (
    CLONE_REMOTE, LOCAL_UPSTREAM, MAX_LOCAL_REF_BYTES, PEELED_TYPES, RESERVED_BRANCH, SEMANTICS_CODES, UNBORN_BRANCH,
    InvalidInput, default_refspec, is_branch, is_local_ref, namespace_conflict, plan_clone, plan_fetch,
)

CONTRACTS = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "acquisitions", "git", "contract")


def contract(name):
    with open(os.path.join(CONTRACTS, name), encoding="utf-8") as file:
        return json.load(file)


FIXTURES = contract("v1/semantics-fixtures.json")


class SemanticsTest(unittest.TestCase):
    def refusal(self, run):
        """The fixed refusal: always the same code and message, never input text."""
        try:
            run()
        except InvalidInput as error:
            self.assertEqual(str(error), "git_semantics_input_invalid")
            return error.code
        return "planned"

    def test_constants_match_the_contract(self):
        spec = contract("v1/contract.json")["semantics"]
        self.assertEqual(spec["codes"], list(SEMANTICS_CODES))
        self.assertEqual(spec["invalid_input"], InvalidInput().code)
        self.assertEqual(spec["unborn_branch"], UNBORN_BRANCH)
        self.assertEqual(spec["clone_remote"], CLONE_REMOTE)
        self.assertEqual(spec["default_refspec"], default_refspec("<remote>"))
        self.assertEqual(spec["peeled_types"], list(PEELED_TYPES))
        self.assertEqual(spec["local_upstream"], LOCAL_UPSTREAM)
        self.assertEqual(spec["max_local_ref_bytes"], MAX_LOCAL_REF_BYTES)
        self.assertEqual(spec["reserved_branch"], RESERVED_BRANCH)

    def test_plans_match_the_frozen_outcomes(self):
        for item in FIXTURES["clone"]:
            self.assertEqual(plan_clone(item["input"]), item["expected"], item["name"])
        for item in FIXTURES["fetch"]:
            self.assertEqual(plan_fetch(item["input"]), item["expected"], item["name"])

    def test_malformed_and_contradictory_inputs_get_the_one_fixed_refusal(self):
        for item in FIXTURES["invalid"]:
            plan = plan_clone if item["operation"] == "clone" else plan_fetch
            self.assertEqual(self.refusal(lambda: plan(item["input"])), "git_semantics_input_invalid", item["name"])

    def test_every_semantics_code_has_a_fixture(self):
        used = {item["expected"]["code"] for item in FIXTURES["clone"] + FIXTURES["fetch"] if not item["expected"]["ok"]}
        self.assertEqual(sorted(used), sorted(SEMANTICS_CODES))

    def test_checkout_targets_the_peeled_commit_while_refs_keep_raw_ids(self):
        detached = 0
        for item in FIXTURES["clone"]:
            plan = plan_clone(item["input"])
            if not plan["ok"] or plan["checkout"]["kind"] == "none":
                continue
            checkout = plan["checkout"]
            name = checkout["branch"] if checkout["kind"] == "branch" else checkout["ref"]
            source = next(ref for ref in item["input"]["acquired"]["refs"] if ref["name"] == name)
            self.assertEqual(source["peeled"]["type"], "commit", item["name"])
            self.assertEqual(checkout["commit"], source["peeled"]["oid"], item["name"])
            created = ("refs/remotes/origin/" + name[len("refs/heads/"):]) if checkout["kind"] == "branch" else name
            self.assertEqual(next(ref["oid"] for ref in plan["refs"] if ref["name"] == created), source["oid"])
            if checkout["kind"] == "detached" and source["oid"] != source["peeled"]["oid"]:
                detached += 1
        self.assertGreaterEqual(detached, 2)

    def test_fetch_never_plans_local_branch_remote_head_or_url_changes(self):
        for item in FIXTURES["fetch"]:
            plan = plan_fetch(item["input"])
            if not plan["ok"]:
                continue
            for update in plan["updates"]:
                self.assertFalse(update["ref"].startswith("refs/heads/"), item["name"])
                self.assertFalse(update["ref"].endswith("/HEAD"), item["name"])
            self.assertNotIn("config", plan)
            self.assertLessEqual(len([entry for entry in plan["fetch_head"] if entry["merge"]]), 1)

    def test_local_ref_order_never_changes_a_plan(self):
        for item in FIXTURES["fetch"]:
            reversed_input = dict(item["input"], local=list(reversed(item["input"]["local"])))
            self.assertEqual(plan_fetch(reversed_input), item["expected"], item["name"])

    def test_clone_persists_only_the_canonical_url_and_default_refspec(self):
        for item in FIXTURES["clone"]:
            plan = plan_clone(item["input"])
            if not plan["ok"]:
                continue
            self.assertEqual([pair for pair in plan["config"] if pair[0].endswith(".url")],
                             [["remote.origin.url", plan["url"]]], item["name"])
            self.assertTrue(all(".agentbox-git" not in value and not value.startswith("/")
                                for _, value in plan["config"]), item["name"])

    def test_local_ref_and_branch_names_are_fully_qualified_and_bounded(self):
        for name in ("refs/heads/main", "refs/tags/v1", "refs/remotes/origin/HEAD", "refs/stash", "refs/notes/commits"):
            self.assertTrue(is_local_ref(name), name)
        for name in ("HEAD", "main", "../bad", "refs/", "refs//x", "refs/heads/a..b",
                     "refs/heads/" + "x" * MAX_LOCAL_REF_BYTES):
            self.assertFalse(is_local_ref(name), name)
        self.assertTrue(is_branch("refs/heads/main"))
        for name in ("refs/heads/HEAD", "refs/tags/v1", "refs/remotes/origin/main", "HEAD"):
            self.assertFalse(is_branch(name), name)

    def test_holes_and_wrong_types_get_the_fixed_refusal_at_every_typed_position(self):
        clone = FIXTURES["clone"][0]["input"]
        fetch = FIXTURES["fetch"][0]["input"]
        url, refspec = fetch["urls"][0], fetch["fetch"][0]

        def holed(items, at):
            items = list(items)
            items[at] = None
            return items

        cases = [
            ("urls [None]", lambda: plan_fetch(dict(fetch, urls=[None]))),
            ("urls with a hole", lambda: plan_fetch(dict(fetch, urls=[url, None]))),
            ("urls a tuple", lambda: plan_fetch(dict(fetch, urls=(url,)))),
            ("refspecs [None]", lambda: plan_fetch(dict(fetch, fetch=[None]))),
            ("refspecs with a hole", lambda: plan_fetch(dict(fetch, fetch=[refspec, None]))),
            ("local refs with a leading hole", lambda: plan_fetch(dict(fetch, local=holed(fetch["local"], 0)))),
            ("local refs with a trailing hole", lambda: plan_fetch(dict(fetch, local=fetch["local"] + [None]))),
            ("fetch acquired refs with a hole", lambda: plan_fetch(
                dict(fetch, acquired=dict(fetch["acquired"], refs=holed(fetch["acquired"]["refs"], 1))))),
            ("clone acquired refs with a hole", lambda: plan_clone(
                dict(clone, acquired=dict(clone["acquired"], refs=holed(clone["acquired"]["refs"], 2))))),
            ("clone acquired refs [None]*3", lambda: plan_clone(
                dict(clone, acquired=dict(clone["acquired"], refs=[None] * 3)))),
        ]
        for name, run in cases:
            self.assertEqual(self.refusal(run), "git_semantics_input_invalid", name)
        self.assertTrue(plan_fetch(dict(fetch, urls=[url], fetch=[refspec]))["ok"])

    def test_namespace_conflicts_are_path_ancestors_not_string_prefixes(self):
        self.assertTrue(namespace_conflict(["refs/remotes/origin/topic", "refs/remotes/origin/topic/new"]))
        self.assertTrue(namespace_conflict(["refs/remotes/origin/topic/a/b", "refs/remotes/origin/topic"]))
        self.assertTrue(namespace_conflict(["refs/remotes/origin", "refs/remotes/origin/main"]))
        self.assertFalse(namespace_conflict(["refs/remotes/origin/topic", "refs/remotes/origin/topic2",
                                             "refs/remotes/origin/topic-x"]))
        self.assertFalse(namespace_conflict(["refs/heads/a", "refs/tags/a/b", "refs/remotes/fork/a/b"]))

    def test_every_successful_plans_resulting_namespace_is_storable(self):
        for item in FIXTURES["clone"]:
            plan = plan_clone(item["input"])
            if not plan["ok"]:
                continue
            names = ([ref["name"] for ref in plan["refs"]]
                     + ([] if "remote_head" not in plan else ["refs/remotes/origin/HEAD"])
                     + ([plan["checkout"]["branch"]] if plan["checkout"]["kind"] == "branch" else []))
            self.assertFalse(namespace_conflict(names), item["name"])
            self.assertFalse(any(name.startswith("refs/remotes/origin/HEAD/") for name in names), item["name"])
        for item in FIXTURES["fetch"]:
            plan = plan_fetch(item["input"])
            if not plan["ok"]:
                continue
            names = {ref["name"] for ref in item["input"]["local"]} | {update["ref"] for update in plan["updates"]}
            self.assertFalse(namespace_conflict(names), item["name"])
            prefix = "refs/remotes/%s/HEAD/" % item["input"]["remote"]
            self.assertFalse(any(name.startswith(prefix) for name in names), item["name"])


if __name__ == "__main__":
    unittest.main()
