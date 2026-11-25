import unittest
from scanner.github_client import validate_url, repo_ref, SSRFBlocked, GitHubError


class GitHubClientTest(unittest.TestCase):
    def test_valid_github_urls_accepted(self):
        validate_url("https://github.com/a/b/releases/download/v1/x.apk")
        validate_url("https://api.github.com/repos/a/b")
        validate_url("https://codeload.github.com/a/b/legacy.zip/refs/tags/v1")

    def test_ssrf_blocked_non_https(self):
        with self.assertRaises(SSRFBlocked):
            validate_url("http://api.github.com/repos/a/b")

    def test_ssrf_blocked_internal_hosts(self):
        for url in ("https://169.254.169.254/latest/meta-data", "https://localhost/x",
                    "https://10.0.0.1/x", "https://evil.example.com/x"):
            with self.assertRaises(SSRFBlocked):
                validate_url(url)

    def test_repo_ref_accepts_owner_slash_repo(self):
        self.assertEqual(repo_ref("2dust/v2rayNG"), "2dust/v2rayNG")

    def test_repo_ref_accepts_full_url(self):
        self.assertEqual(repo_ref("https://github.com/2dust/v2rayNG"), "2dust/v2rayNG")
        self.assertEqual(repo_ref("https://github.com/2dust/v2rayNG.git"), "2dust/v2rayNG")
        self.assertEqual(repo_ref("https://github.com/2dust/v2rayNG/releases"), "2dust/v2rayNG")

    def test_repo_ref_rejects_non_github(self):
        with self.assertRaises(SSRFBlocked):
            repo_ref("https://gitlab.com/a/b")

    def test_repo_ref_rejects_shell_metacharacters(self):
        with self.assertRaises(GitHubError):
            repo_ref("a/b; rm -rf /")
        with self.assertRaises(GitHubError):
            repo_ref("a/b && curl evil")


if __name__ == "__main__":
    unittest.main()
