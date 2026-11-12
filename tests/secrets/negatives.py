"""Hard negatives: strings that look secret-ish but must reach the upstream unchanged.

Each negative is (id, build(rng) -> str). Random parts are generated from a seeded RNG
so runs are reproducible. Placed into NEGATIVE_CONTEXTS by run.py.
"""
import random

import formats

NEGATIVE_CONTEXTS = ["prompt_text", "read_result_tab"]


def _uuid(rng):
    h = formats.expand("{h:32}", rng)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:32]}"


CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid(rng):
    return "0" + rng.choice("1234567") + "".join(rng.choice(CROCKFORD) for _ in range(24))


def _upper_id(rng, prefix):
    """A chat-style id: a type letter, a digit, then upper-case letters and digits (U0ABCD12E)."""
    return prefix + "0" + formats.expand("{L:4}", rng).upper() + formats.expand("{A:4}", rng)


def _git_log(rng):
    msgs = ["Fix flaky checkout test", "Bump axum to 0.8", "Add retry to uploader", "Refactor config loader",
            "Document the release process"]
    return "\n".join(formats.expand("{h:7}", rng) + " " + m for m in msgs)


E = formats.expand
NEGATIVES = [
    ("uuid_v4", lambda r: f"request {_uuid(r)} returned 200"),
    ("anthropic_request_id", lambda r: "request id req_011C" + E("{b62:20}", r) + " was rate limited"),
    ("git_sha_full", lambda r: "Reverted in commit " + E("{h:40}", r)),
    ("git_sha_short", lambda r: "see " + E("{h:7}", r) + " for the fix"),
    ("git_log_oneline", _git_log),
    ("docker_digest", lambda r: "image: ghcr.io/acme/api@sha256:" + E("{h:64}", r)),
    ("npm_integrity", lambda r: '"integrity": "sha512-' + E("{b64:86}", r) + '=="'),
    ("go_sum", lambda r: "github.com/pkg/errors v0.9.1 h1:" + E("{b64:43}", r) + "="),
    ("md5sum_line", lambda r: E("{h:32}", r) + "  dist/app.tar.gz"),
    ("js_chunk_hash", lambda r: "dist/assets/index-" + E("{h:8}", r) + ".js"),
    ("env_ref_dollar", lambda r: "curl -H \"Authorization: Bearer $API_KEY\" https://api.internal"),
    ("env_ref_braces", lambda r: "export TOKEN=${API_KEY}"),
    ("env_ref_process_env", lambda r: "const key = process.env.API_KEY;"),
    ("env_ref_os_environ", lambda r: 'key = os.environ["API_KEY"]'),
    ("env_ref_getenv", lambda r: 'key = os.getenv("API_KEY")'),
    ("env_ref_ruby", lambda r: "key = ENV['API_KEY']"),
    ("env_ref_gha_secret", lambda r: "token: ${{ secrets.API_KEY }}"),
    ("env_ref_helm", lambda r: "apiKey: {{ .Values.apiKey }}"),
    ("placeholder_your_key", lambda r: "API_KEY=YOUR_API_KEY_HERE"),
    ("placeholder_angle", lambda r: "TOKEN=<your-token>"),
    ("placeholder_changeme", lambda r: "DB_PASSWORD=changeme"),
    ("placeholder_xxx", lambda r: "SECRET=xxxxxxxxxxxxxxxx"),
    ("placeholder_ellipsis", lambda r: "use a key like sk-... from the dashboard"),
    ("placeholder_stars", lambda r: "password: ***"),
    ("piifence_env_ref", lambda r: 'curl -H "Authorization: Bearer $PIIF_SECRET_1" https://api.internal'),
    ("hex_colors", lambda r: "colors: #1f2937 #f59e0b #10b981"),
    ("semver", lambda r: "upgraded from 1.24.3 to 2.0.0-rc.1"),
    ("iso_timestamp", lambda r: "started at 2026-10-30T12:34:56.789Z"),
    ("container_id", lambda r: "container " + E("{h:12}", r) + " exited with code 0"),
    ("k8s_pod_name", lambda r: "pod api-7d9f8b6c5-" + E("{a:5}", r) + " is Running"),
    ("aws_arn", lambda r: "role arn:aws:iam::123456789012:role/deploy-role"),
    ("localhost_port", lambda r: "listening on 127.0.0.1:8080"),
    ("code_call_assignment", lambda r: "let token = next_placeholder(state, label);"),
    ("code_method_chain", lambda r: "let secret = finding.secret.as_str();"),
    ("code_rust_macro", lambda r: "colon_token: Token![:],"),
    ("code_path", lambda r: "paren_token: token::Paren,"),
    ("json_object_value", lambda r: '"secret": {"categories": ["secret"]}'),
    # Claude Code's own ids and paths: the session UUID is in every scripts path.
    ("claude_session_path", lambda r: f"cd ~/.claude/projects/-Users-me-app/{_uuid(r)}/scripts && python3 check.py"),
    ("claude_transcript_path", lambda r: f"read ~/.claude/projects/-Users-me-app/{_uuid(r)}.jsonl"),
    ("tool_use_id", lambda r: '"tool_use_id": "toolu_01' + E("{b62:22}", r) + '"'),
    ("sed_range", lambda r: "sed -n '" + E("{d:3}", r) + "," + E("{d:4}", r) + "p' session.jsonl"),
    # Other ids and hashes.
    ("guid_upper_braces", lambda r: "CLSID {" + _uuid(r).upper() + "}"),
    ("mongo_object_id", lambda r: 'db.users.find({_id: ObjectId("' + E("{h:24}", r) + '")})'),
    ("ulid", lambda r: "event " + _ulid(r) + " was delivered"),
    ("aws_instance_id", lambda r: "instance i-0" + E("{h:16}", r) + " stopped"),
    ("sha256_checksum", lambda r: 'checksum = "sha256:' + E("{h:64}", r) + '"'),
    ("hashed_css", lambda r: "dist/assets/app." + E("{h:8}", r) + ".css"),
    ("hex_fixture", lambda r: 'const HEX: &str = "0123456789abcdef";'),
    # Stand-ins for a value.
    ("masked_bullets", lambda r: "token: ••••••••"),
    ("template_literal", lambda r: 'value = "sk-{b62:20}"'),
    ("example_name", lambda r: 'name = "piifence-example"'),
    ("placeholder_word_value", lambda r: "            DEPLOY_TOKEN: 'deploy-token',"),
    ("placeholder_invalid_token", lambda r: "JWT validation error: Invalid JWT Bearer token: 'invalid-token'"),
    # Shapes seen in real sessions (tests/secrets/mined.jsonl has the rest).
    # Joined at run time so the repo's own gitleaks scan does not read the literal as a curl password.
    ("curl_user_env_reference", lambda r: ":".join(['curl -s -u "$SONAR_TOKEN', '" "https://sonar.acme.dev/api/issues/search?resolved=false"'])),
    ("curl_user_env_defaults", lambda r: ":".join(['curl -s -u "${JIRA_EMAIL', "-$ATL_EMAIL}", "${JIRA_API_TOKEN", '-$ATL_API_TOKEN}" "$BASE/rest/api/3/myself"'])),
    ("url_value_in_json", lambda r: '{"cp":"https://www.acme.dev","env":"testing","login":"dev@acme.dev","success":true}'),
    ("ci_duration_table", lambda r: "test / build\tpass\t2m34s\thttps://ci.acme.dev/run/" + E("{d:10}", r)),
    ("chat_ids_in_shell_loop", lambda r: "for u in " + " ".join(_upper_id(r, p) for p in "UUU") + "; do ./slack users-info --user $u; done"),
    ("chat_id_constant", lambda r: f"SLACK_CHANNEL = '{_upper_id(r, 'C')}'"),
]


class Negative:
    """Adapts a negative to the formats.Format interface used by contexts."""

    family = "negative"

    def __init__(self, nid, build):
        self.id = nid
        self._build = build

    def generate(self, salt="0"):
        value = self._build(random.Random(f"neg|{self.id}|{salt}"))
        return formats.Generated(self.id, "negative", value, [], value, None, "\n" in value)


ALL = [Negative(nid, b) for nid, b in NEGATIVES]
