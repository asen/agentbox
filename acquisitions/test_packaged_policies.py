"""The packaged default policies (git/npm/pip `policy.json`, the
controller's selection without an acquisition configuration) as each
worker's own policy check reads them. Offline: nothing is fetched.

    python3 -I -B -m unittest discover -s acquisitions -p 'test_*.py'
"""
import importlib.util
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.dont_write_bytecode = True


def policy(ident):
    with open(os.path.join(HERE, ident, "policy.json")) as stream:
        return json.load(stream)


def worker(ident):
    spec = importlib.util.spec_from_file_location(f"packaged_{ident}_worker",
                                                  os.path.join(HERE, ident, "host", "worker.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PackagedPolicies(unittest.TestCase):
    def test_pip_reads_pypi_and_its_file_host(self):
        index, origins = worker("pip").approved(policy("pip"))
        self.assertEqual(origins, ["https://files.pythonhosted.org/packages/"])
        self.assertEqual(policy("pip")["index"], "https://pypi.org/simple/")
        self.assertTrue(index)

    def test_npm_reads_the_public_registry(self):
        self.assertEqual(worker("npm").registry_of(policy("npm")), ("registry.npmjs.org", "/"))

    def test_npm_matches_the_installers_policy(self):
        with open(os.path.join(os.path.dirname(HERE), "agents", "npm-registry.json")) as stream:
            self.assertEqual(policy("npm"), json.load(stream))

    def test_git_reads_any_public_github_repository(self):
        git = worker("git")
        self.assertEqual(policy("git"), {"schema": git.POLICY_SCHEMA, "grant": git.GRANT})
        self.assertTrue(git.policy_permits(policy("git"), "octocat/hello-world"))


if __name__ == "__main__":
    unittest.main()
