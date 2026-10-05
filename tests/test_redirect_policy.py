"""End-to-end credential and redirect policy checks against owned loopback servers."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from redirect_credential_boundary import (
    RedirectClient,
    RedirectLimitError,
    RedirectLoopError,
    ResponseTooLargeError,
    UnsafeUrlError,
)

from lab_support import LoopbackLab
from redirect_credential_boundary.client import _parse_url


_AUTH = "Bearer SYNTHETIC_LAB_TOKEN"
_COOKIE = "lab_session=SYNTHETIC_LAB_COOKIE"


class RedirectPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lab = LoopbackLab()
        self.lab.__enter__()

    def tearDown(self) -> None:
        self.lab.__exit__(None, None, None)

    def test_cross_port_origin_strips_both_credentials(self) -> None:
        result = RedirectClient().get(
            self.lab.a_url + "/cross", headers={"aUtHoRiZaTiOn": _AUTH, "COOKIE": _COOKIE}
        )
        records = self.lab.snapshot()
        self.assertEqual(result.status, 200)
        self.assertEqual([item["origin"] for item in records], ["A", "B"])
        self.assertEqual(records[0]["authorization"], _AUTH)
        self.assertEqual(records[0]["cookie"], _COOKIE)
        self.assertIsNone(records[1]["authorization"])
        self.assertIsNone(records[1]["cookie"])
        self.assertEqual(set(result.history[0].stripped_header_names), {"aUtHoRiZaTiOn", "COOKIE"})

    def test_relative_same_origin_keeps_credentials(self) -> None:
        result = RedirectClient().get(
            self.lab.a_url + "/relative", headers={"Authorization": _AUTH, "Cookie": _COOKIE}
        )
        records = self.lab.snapshot()
        self.assertEqual(result.status, 200)
        self.assertEqual([item["origin"] for item in records], ["A", "A"])
        self.assertEqual(records[1]["authorization"], _AUTH)
        self.assertEqual(records[1]["cookie"], _COOKIE)
        self.assertEqual(result.history[0].stripped_header_names, ())
        self.assertTrue(result.url.endswith("/capture?case=relative"))

    def test_mixed_case_hostname_is_same_origin(self) -> None:
        result = RedirectClient().get(
            f"http://localhost:{self.lab.a_port}/mixed",
            headers={"Authorization": _AUTH, "Cookie": _COOKIE},
        )
        records = self.lab.snapshot()
        self.assertEqual(result.status, 200)
        self.assertEqual([item["origin"] for item in records], ["A", "A"])
        self.assertEqual(records[1]["authorization"], _AUTH)
        self.assertEqual(records[1]["cookie"], _COOKIE)

    def test_explicit_second_origin_opt_in(self) -> None:
        result = RedirectClient(credential_redirects=((self.lab.a_url, self.lab.b_url),)).get(
            self.lab.a_url + "/cross", headers={"Authorization": _AUTH, "Cookie": _COOKIE}
        )
        self.assertEqual(result.status, 200)
        self.assertEqual(self.lab.snapshot()[-1]["authorization"], _AUTH)
        self.assertEqual(self.lab.snapshot()[-1]["cookie"], _COOKIE)

    def test_explicit_cross_origin_exception_is_directional(self) -> None:
        result = RedirectClient(
            credential_redirects=((self.lab.a_url, self.lab.b_url),)
        ).get(self.lab.a_url + "/cross-return", headers={"Authorization": _AUTH})
        records = self.lab.snapshot()
        self.assertEqual(result.status, 200)
        self.assertEqual([item["origin"] for item in records], ["A", "B", "A"])
        self.assertEqual(records[1]["authorization"], _AUTH)
        self.assertIsNone(records[2]["authorization"])

    def test_scheme_and_default_port_are_part_of_origin(self) -> None:
        self.assertEqual(
            _parse_url("HTTP://LOCALHOST:80/")[1], _parse_url("http://localhost/")[1]
        )
        self.assertNotEqual(
            _parse_url("http://localhost/")[1], _parse_url("https://localhost/")[1]
        )

    def test_https_downgrade_strips_even_an_explicit_exception(self) -> None:
        source = "https://localhost:4433/start"
        destination = "http://localhost:8080/capture"
        sent_headers: list[dict[str, str]] = []

        def fake_send(_client, _parts, _origin, headers):
            sent_headers.append(dict(headers))
            if len(sent_headers) == 1:
                return 302, (), b"", destination
            return 200, (), b"ok", None

        with patch.object(RedirectClient, "_send_get", fake_send):
            result = RedirectClient(
                credential_redirects=(("https://localhost:4433", "http://localhost:8080"),)
            ).get(source, headers={"Authorization": _AUTH})
        self.assertEqual(result.status, 200)
        self.assertEqual(sent_headers[0]["Authorization"], _AUTH)
        self.assertNotIn("Authorization", sent_headers[1])

    def test_stripped_credentials_do_not_reappear_on_return(self) -> None:
        result = RedirectClient().get(
            self.lab.a_url + "/cross-return", headers={"Authorization": _AUTH, "Cookie": _COOKIE}
        )
        records = self.lab.snapshot()
        self.assertEqual(result.status, 200)
        self.assertEqual([item["origin"] for item in records], ["A", "B", "A"])
        self.assertIsNone(records[1]["authorization"])
        self.assertIsNone(records[2]["authorization"])
        self.assertIsNone(records[2]["cookie"])

    def test_loop_and_limit_are_bounded(self) -> None:
        with self.assertRaises(RedirectLoopError):
            RedirectClient().get(self.lab.a_url + "/loop")
        self.lab.clear()
        with self.assertRaises(RedirectLimitError):
            RedirectClient(max_redirects=2).get(self.lab.a_url + "/count/0")
        self.assertEqual(len(self.lab.snapshot()), 3)

    def test_unsupported_redirect_scheme_is_rejected(self) -> None:
        with self.assertRaises(UnsafeUrlError):
            RedirectClient().get(self.lab.a_url + "/unsafe")

    def test_custom_credential_header_can_be_removed(self) -> None:
        result = RedirectClient(credential_header_names=("X-Lab-Token",)).get(
            self.lab.a_url + "/cross", headers={"X-Lab-Token": "synthetic"}
        )
        self.assertEqual(result.status, 200)
        self.assertEqual(result.history[0].stripped_header_names, ("X-Lab-Token",))

    def test_cross_origin_strips_sensitive_referer(self) -> None:
        value = self.lab.a_url + "/view?token=SYNTHETIC_LAB_TOKEN"
        result = RedirectClient().get(
            self.lab.a_url + "/cross", headers={"Referer": value}
        )
        records = self.lab.snapshot()
        self.assertEqual(result.status, 200)
        self.assertEqual(records[0]["referer"], value)
        self.assertIsNone(records[1]["referer"])
        self.assertEqual(result.history[0].stripped_header_names, ("Referer",))

    def test_proxy_authorization_is_rejected_without_proxy_support(self) -> None:
        with self.assertRaisesRegex(ValueError, "Proxy-Authorization"):
            RedirectClient().get(
                self.lab.a_url + "/capture",
                headers={"pRoXy-AuThOrIzAtIoN": "Basic SYNTHETIC_LAB_TOKEN"},
            )
        self.assertEqual(self.lab.snapshot(), [])

    def test_unencodable_header_is_rejected_before_sending(self) -> None:
        with self.assertRaisesRegex(ValueError, "Latin-1") as error:
            RedirectClient().get(
                self.lab.a_url + "/capture",
                headers={"Authorization": "Bearer 雪 SYNTHETIC_LAB_TOKEN"},
            )
        self.assertNotIn("SYNTHETIC_LAB_TOKEN", str(error.exception))
        self.assertEqual(self.lab.snapshot(), [])

    def test_history_records_only_origins_without_query_tokens(self) -> None:
        token = "SYNTHETIC_QUERY_TOKEN"
        result = RedirectClient().get(self.lab.a_url + "/cross?token=" + token)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.history[0].from_origin, self.lab.a_url)
        self.assertEqual(result.history[0].to_origin, self.lab.b_url)
        self.assertNotIn(token, repr(result.history))

    def test_invalid_initial_target_does_not_echo_query_token(self) -> None:
        token = "SYNTHETIC_QUERY_TOKEN"
        with self.assertRaises(UnsafeUrlError) as error:
            RedirectClient().get(self.lab.a_url + "/a b?token=" + token)
        self.assertNotIn(token, str(error.exception))
        self.assertEqual(self.lab.snapshot(), [])

    def test_leading_c0_control_is_rejected_before_urlsplit(self) -> None:
        token = "SYNTHETIC_QUERY_TOKEN"
        with self.assertRaises(UnsafeUrlError) as error:
            RedirectClient().get("\x00" + self.lab.a_url + "/capture?token=" + token)
        self.assertNotIn(token, str(error.exception))
        self.assertEqual(self.lab.snapshot(), [])

    def test_non_ascii_request_target_is_rejected_before_sending(self) -> None:
        token = "SYNTHETIC_QUERY_TOKEN"
        for path in ("/中文?token=" + token, "/capture?token=雪" + token):
            with self.subTest(path=path), self.assertRaises(UnsafeUrlError) as error:
                RedirectClient().get(self.lab.a_url + path)
            self.assertNotIn(token, str(error.exception))
        self.assertEqual(self.lab.snapshot(), [])

    def test_non_ascii_redirect_target_is_rejected(self) -> None:
        token = "SYNTHETIC_QUERY_TOKEN"
        calls = 0

        def fake_send(_client, _parts, _origin, _headers):
            nonlocal calls
            calls += 1
            return 302, (), b"", "/中文?token=" + token

        with patch.object(RedirectClient, "_send_get", fake_send):
            with self.assertRaises(UnsafeUrlError) as error:
                RedirectClient().get(self.lab.a_url + "/start")
        self.assertEqual(calls, 1)
        self.assertNotIn(token, str(error.exception))

    def test_invalid_redirect_target_does_not_echo_query_token(self) -> None:
        token = "SYNTHETIC_LAB_TOKEN"
        with self.assertRaises(UnsafeUrlError) as error:
            RedirectClient().get(self.lab.a_url + "/unsafe-space")
        self.assertNotIn(token, str(error.exception))
        self.assertEqual([entry["origin"] for entry in self.lab.snapshot()], ["A"])

    def test_response_body_limit(self) -> None:
        with self.assertRaises(ResponseTooLargeError):
            RedirectClient(max_body_bytes=16).get(self.lab.a_url + "/large")

    def test_invalid_initial_inputs_are_rejected(self) -> None:
        with self.assertRaises(UnsafeUrlError):
            RedirectClient().get("http://someone:password@127.0.0.1/")
        with self.assertRaises(UnsafeUrlError):
            RedirectClient().get("http://127.0.0.1/\n")
        with self.assertRaises(UnsafeUrlError):
            RedirectClient().get("http://127.0.0.1:0/")
        with self.assertRaises(ValueError):
            RedirectClient().get(self.lab.a_url + "/capture", headers={"Host": "elsewhere"})
        with self.assertRaises(UnsafeUrlError):
            RedirectClient(credential_redirects=((self.lab.a_url + "/path", self.lab.b_url),))


if __name__ == "__main__":
    unittest.main()
