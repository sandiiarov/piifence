"""Secret format catalogue for the end-to-end secret suite.

Every value is generated at runtime from a seeded RNG, so no secret-shaped literal is
ever written to the repo (keeps `gitleaks dir` clean and avoids push protection).
The same format id and salt always give the same value.

Template language (see `expand`):
  {A:n} upper letters+digits   {a:n} lower letters+digits   {L:n} letters
  {h:n} lower hex   {H:n} upper hex   {d:n} digits   {b62:n} base62
  {b64:n} base64 chars   {b64url:n} base64url chars   {B32:n} A-Z2-7
  {BECH:n} upper-case bech32 chars   {pw:n} human-style password
  {at} a literal "@" (so URL templates here do not look like URL credentials)

A format's `rules` lists the gitleaks rule ids (gitleaks 8.30.1 default config plus
the repo's gitleaks.toml) expected to match its `line`; None means "not checked"
(no rule exists, or a match is not required). `run.py --check-generators` verifies it.
"""
import base64
import dataclasses
import json
import random
import re
import string

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
CLASSES = {
    "A": UPPER + DIGITS,
    "a": LOWER + DIGITS,
    "L": UPPER + LOWER,
    "h": "0123456789abcdef",
    "H": "0123456789ABCDEF",
    "d": DIGITS,
    "b62": UPPER + LOWER + DIGITS,
    "b64": UPPER + LOWER + DIGITS + "+/",
    "b64url": UPPER + LOWER + DIGITS + "-_",
    "B32": UPPER + "234567",
    "BECH": "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L",
}
PW_SYMBOLS = "!#%&*-_."
TOKEN_RE = re.compile(r"\{(A|a|L|h|H|d|b62|b64|b64url|B32|BECH|pw):(\d+)\}|\{at\}")


def password(rng, n):
    """A human-style password: letters and digits with at least one symbol."""
    chars = [rng.choice(UPPER + LOWER + DIGITS) for _ in range(n - 2)]
    chars.insert(rng.randrange(len(chars) + 1), rng.choice(PW_SYMBOLS))
    chars.insert(rng.randrange(len(chars) + 1), rng.choice(DIGITS))
    return "".join(chars)


def expand(template, rng):
    def sub(m):
        if m.group(0) == "{at}":
            return "@"
        kind, n = m.group(1), int(m.group(2))
        if kind == "pw":
            return password(rng, n)
        return "".join(rng.choice(CLASSES[kind]) for _ in range(n))

    return TOKEN_RE.sub(sub, template)


def leak_variants(secret):
    """Forms a secret can take inside a request string: as-is, and JSON-escaped (when
    a tool wrote it into a JSON document, quotes and backslashes gain a backslash)."""
    return {secret, json.dumps(secret)[1:-1]}


@dataclasses.dataclass
class Generated:
    """One generated value. `secrets` are the substrings that must never leak;
    `line` is how the value appears in a config or env file."""

    format_id: str
    family: str
    full: str
    secrets: list
    line: str
    var: str = None
    multiline: bool = False


@dataclasses.dataclass
class Format:
    id: str
    family: str
    template: str = None
    build: object = None  # callable(rng) -> (full, secrets, line or None)
    var: str = None
    rules: tuple = None
    multiline: bool = False

    def generate(self, salt="0"):
        rng = random.Random(f"{self.id}|{salt}")
        if self.build:
            full, secrets, line = self.build(rng)
        else:
            full = expand(self.template, rng)
            secrets, line = [full], None
        if line is None:
            line = f"{self.var}={full}" if self.var else full
        return Generated(self.id, self.family, full, secrets, line, self.var, self.multiline)


# --- composite builders -------------------------------------------------------


def _pem(kind):
    def build(rng):
        body = ["".join(rng.choice(CLASSES["b64"]) for _ in range(64)) for _ in range(10)]
        tail = "".join(rng.choice(CLASSES["b64"]) for _ in range(40)) + "=="
        label = (kind + " ") if kind else ""
        header = "-----BEGIN " + label + "PRIVATE KEY-----"
        footer = "-----END " + label + "PRIVATE KEY-----"
        if kind == "PGP":
            header = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
            footer = "-----END PGP PRIVATE KEY BLOCK-----"
        full = "\n".join([header] + body + [tail, footer])
        return full, body, full

    return build


def _gcp_service_account(rng):
    pem, body, _ = _pem("")(rng)
    project = "proj-" + expand("{a:6}", rng)
    doc = (
        '{"type": "service_account", "project_id": "%s", "private_key_id": "%s", '
        '"private_key": "%s\\n", "client_email": "deployer%s%s.iam.gserviceaccount.com"}'
        % (project, expand("{h:40}", rng), pem.replace("\n", "\\n"), "@", project)
    )
    return doc, body, doc


def _basic_auth(rng):
    token = base64.b64encode(("deploy:" + password(rng, 16)).encode()).decode()
    return token, [token], "Authorization: Basic " + token


def _bearer(rng):
    token = expand("{b62:40}", rng)
    return token, [token], "Authorization: Bearer " + token


def _url(prefix, user, n, suffix):
    def build(rng):
        pw = password(rng, n)
        return prefix + user + ":" + pw + "@" + suffix, [pw], None

    return build


def _git_https_token(rng):
    tok = "ghp" + "_" + expand("{b62:36}", rng)
    return "https://x-access-token:" + tok + "@github.com/acme/app.git", [tok], None


def _sqlserver(rng):
    pw = password(rng, 18)
    return "Server=tcp:sql.internal,1433;Database=app;User Id=sa;Password=" + pw + ";", [pw], None


def _jdbc(rng):
    pw = password(rng, 16)
    return "jdbc:postgresql://db.internal/app?user=app&password=" + pw, [pw], None


def _kube_token(rng):
    tok = expand("{b64url:120}", rng)
    return tok, [tok], "    token: " + tok


def _docker_auth(rng):
    tok = base64.b64encode(("ci-bot:" + password(rng, 20)).encode()).decode()
    return tok, [tok], '{"auths": {"https://index.docker.io/v1/": {"auth": "' + tok + '"}}}'


def _netrc(rng):
    tok = expand("{b62:40}", rng)
    return tok, [tok], "machine github.com login bot password " + tok


def _pw_quote_backslash(rng):
    pw = (expand("{b62:6}", rng) + '"' + expand("{b62:4}", rng) + "'"
          + expand("{b62:3}", rng) + "\\" + expand("{d:3}", rng))
    return pw, [pw], None


def _pw_dollar_space(rng):
    pw = expand("{b62:5}", rng) + "$" + expand("{b62:4}", rng) + " " + expand("{b62:6}", rng)
    return pw, [pw], None


def _bare_hex(rng):
    tok = expand("{h:32}", rng)
    return tok, [tok], tok


def _azure_conn(rng):
    key = expand("{b64:86}", rng) + "=="
    full = ("DefaultEndpointsProtocol=https;AccountName=acme" + expand("{a:6}", rng)
            + ";AccountKey=" + key + ";EndpointSuffix=core.windows.net")
    return full, [key], "AZURE_STORAGE_CONNECTION_STRING=" + full


def _discord_webhook(rng):
    token = expand("{b64url:68}", rng)
    return expand("https://discord.com/api/webhooks/{d:18}/", rng) + token, [token], None


def _azure_sas(rng):
    sig = expand("{b64url:43}", rng)
    full = "sv=2022-11-02&ss=b&srt=sco&sp=rwdlac&se=2027-01-01T00:00:00Z&sig=" + sig + "%3D"
    return full, [sig], None


F = Format
FORMATS = [
    # cloud
    F("aws_access_key_id", "cloud", "AKIA{B32:16}", var="AWS_ACCESS_KEY_ID",
      rules=("aws-access-token", "piifence-aws-access-token")),
    F("aws_secret_access_key", "cloud", "{b64:40}", var="AWS_SECRET_ACCESS_KEY", rules=("generic-api-key", "piifence-password-assignment")),
    F("gcp_api_key", "cloud", "AIza{b64url:35}", var="GOOGLE_API_KEY", rules=("gcp-api-key",)),
    F("gcp_service_account_json", "cloud", build=_gcp_service_account, multiline=True),
    F("azure_storage_conn_string", "cloud", build=_azure_conn, rules=("piifence-azure-storage-account-key",)),
    F("azure_ad_client_secret", "cloud", "{L:3}{d:1}Q~{b64url:34}", var="AZURE_CLIENT_SECRET",
      rules=("azure-ad-client-secret",)),
    F("azure_sas_signature", "cloud", build=_azure_sas, var="AZURE_SAS", rules=("piifence-azure-sas-signature",)),
    F("digitalocean_pat", "cloud", "dop_v1_{h:64}", var="DIGITALOCEAN_TOKEN", rules=("digitalocean-pat",)),
    F("heroku_api_key_v2", "cloud", "HRKU-AA{b64url:58}", var="HEROKU_API_KEY", rules=("heroku-api-key-v2",)),
    F("alibaba_access_key_id", "cloud", "LTAI{a:20}", var="ALIBABA_ACCESS_KEY_ID", rules=("alibaba-access-key-id",)),
    F("cloudflare_api_token", "cloud", "{a:40}", var="CLOUDFLARE_API_TOKEN",
      rules=("cloudflare-api-key", "generic-api-key")),
    # vcs
    F("github_pat_classic", "vcs", "ghp_{b62:36}", var="GITHUB_TOKEN", rules=("github-pat",)),
    F("github_oauth", "vcs", "gho_{b62:36}", var="GH_OAUTH_TOKEN", rules=("github-oauth",)),
    F("github_user_to_server", "vcs", "ghu_{b62:36}", var="GH_USER_TOKEN", rules=("github-app-token",)),
    F("github_server_to_server", "vcs", "ghs_{b62:36}", var="GH_APP_TOKEN", rules=("github-app-token",)),
    F("github_refresh", "vcs", "ghr_{b62:36}", var="GH_REFRESH_TOKEN", rules=("github-refresh-token",)),
    F("github_fine_grained_pat", "vcs", "github_pat_11{A:20}_{b62:59}", var="GITHUB_PAT",
      rules=("github-fine-grained-pat",)),
    F("gitlab_pat", "vcs", "glpat-{b64url:20}", var="GITLAB_TOKEN", rules=("gitlab-pat",)),
    F("gitlab_pipeline_trigger", "vcs", "glptt-{h:40}", var="GITLAB_TRIGGER_TOKEN", rules=("gitlab-ptt",)),
    F("gitlab_runner_token", "vcs", "glrt-{b64url:20}", var="RUNNER_TOKEN",
      rules=("gitlab-runner-authentication-token",)),
    F("atlassian_api_token", "vcs", "ATATT3{b64url:186}", var="ATLASSIAN_API_TOKEN", rules=("piifence-atlassian-api-token",)),
    # ai
    F("anthropic_api_key", "ai", "sk-ant-api03-{b64url:93}AA", var="ANTHROPIC_API_KEY", rules=("anthropic-api-key", "piifence-anthropic-key")),
    F("anthropic_admin_key", "ai", "sk-ant-admin01-{b64url:93}AA", var="ANTHROPIC_ADMIN_KEY",
      rules=("anthropic-admin-api-key", "piifence-anthropic-key")),
    F("openai_project_key", "ai", "sk-proj-{b64url:74}T3BlbkFJ{b64url:74}", var="OPENAI_API_KEY",
      rules=("openai-api-key", "piifence-openai-project-key")),
    F("openai_project_key_short", "ai", "sk-proj-{b64url:48}", var="OPENAI_API_KEY",
      rules=("piifence-openai-project-key",)),
    F("openai_legacy_key", "ai", "sk-{b62:20}T3BlbkFJ{b62:20}", var="OPENAI_API_KEY", rules=("openai-api-key",)),
    F("huggingface_token", "ai", "hf_{L:34}", var="HF_TOKEN", rules=("huggingface-access-token",)),
    F("openrouter_key", "ai", "sk-or-v1-{h:64}", var="OPENROUTER_API_KEY", rules=("piifence-openrouter-key",)),
    F("groq_key", "ai", "gsk_{b62:52}", var="GROQ_API_KEY", rules=("piifence-groq-key",)),
    F("replicate_token", "ai", "r8_{b62:37}", var="REPLICATE_API_TOKEN", rules=("piifence-replicate-token",)),
    F("perplexity_key", "ai", "pplx-{b62:48}", var="PERPLEXITY_API_KEY", rules=("perplexity-api-key",)),
    F("xai_key", "ai", "xai-{b62:80}", var="XAI_API_KEY", rules=("piifence-xai-key",)),
    F("cohere_key", "ai", "{b62:40}", var="COHERE_API_KEY", rules=("cohere-api-token", "generic-api-key")),
    F("opencode_key", "ai", "oc_sk_{h:32}", var="OPENCODE_API_KEY", rules=("piifence-opencode-key",)),
    # payments
    F("stripe_live_secret", "payments", "sk_live_{b62:24}", var="STRIPE_SECRET_KEY", rules=("stripe-access-token", "piifence-stripe-secret-key")),
    F("stripe_restricted", "payments", "rk_live_{b62:24}", var="STRIPE_RESTRICTED_KEY", rules=("stripe-access-token", "piifence-stripe-secret-key")),
    F("stripe_test_secret", "payments", "sk_test_{b62:24}", var="STRIPE_TEST_KEY", rules=("stripe-access-token", "piifence-stripe-secret-key")),
    F("stripe_webhook_secret", "payments", "whsec_{b62:32}", var="STRIPE_WEBHOOK_SECRET", rules=("piifence-stripe-webhook-secret",)),
    F("square_access_token", "payments", "EAAA{b64url:60}", var="SQUARE_ACCESS_TOKEN", rules=("square-access-token",)),
    F("braintree_access_token", "payments", "access_token$production${a:16}${h:32}", var="BRAINTREE_TOKEN", rules=("piifence-braintree-access-token",)),
    # comms
    F("slack_bot_token", "comms", "xoxb-{d:11}-{d:13}-{b62:24}", var="SLACK_BOT_TOKEN", rules=("slack-bot-token",)),
    F("slack_user_token", "comms", "xoxp-{d:11}-{d:11}-{d:13}-{h:32}", var="SLACK_USER_TOKEN",
      rules=("slack-user-token",)),
    F("slack_app_token", "comms", "xapp-1-A{A:10}-{d:13}-{h:64}", var="SLACK_APP_TOKEN", rules=("slack-app-token",)),
    F("slack_webhook_url", "comms", "https://hooks.slack.com/services/T{A:8}/B{A:10}/{b62:24}",
      var="SLACK_WEBHOOK_URL", rules=("slack-webhook-url",)),
    F("discord_webhook_url", "comms", build=_discord_webhook, var="DISCORD_WEBHOOK", rules=("piifence-discord-webhook",)),
    F("twilio_api_key", "comms", "SK{h:32}", var="TWILIO_API_KEY", rules=("twilio-api-key",)),
    F("sendgrid_key", "comms", "SG.{b64url:22}.{b64url:43}", var="SENDGRID_API_KEY", rules=("sendgrid-api-token",)),
    F("mailgun_key", "comms", "key-{h:32}", var="MAILGUN_API_KEY", rules=("mailgun-private-api-token",)),
    F("mailchimp_key", "comms", "{h:32}-us{d:2}", var="MAILCHIMP_API_KEY", rules=("mailchimp-api-key",)),
    F("telegram_bot_token", "comms", "{d:10}:A{b64url:34}", var="TELEGRAM_BOT_TOKEN",
      rules=("telegram-bot-api-token",)),
    # registries
    F("npm_token", "registry", "npm_{b62:36}", var="NPM_TOKEN", rules=("npm-access-token",)),
    F("pypi_token", "registry", "pypi-AgEIcHlwaS5vcmc{b64url:70}", var="PYPI_TOKEN", rules=("pypi-upload-token",)),
    F("rubygems_key", "registry", "rubygems_{h:48}", var="GEM_HOST_API_KEY", rules=("rubygems-api-token",)),
    F("nuget_key", "registry", "oy2{a:43}", var="NUGET_API_KEY", rules=("piifence-nuget-key",)),
    F("dockerhub_pat", "registry", "dckr_pat_{b64url:27}", var="DOCKERHUB_TOKEN", rules=("piifence-dockerhub-pat",)),
    # saas
    F("vault_service_token", "saas", "hvs.{b64url:90}", var="VAULT_TOKEN", rules=("vault-service-token",)),
    F("terraform_cloud_token", "saas", "{b62:14}.atlasv1.{b64url:67}", var="TFE_TOKEN",
      rules=("hashicorp-tf-api-token",)),
    F("doppler_token", "saas", "dp.pt.{b62:43}", var="DOPPLER_TOKEN", rules=("doppler-api-token",)),
    F("pulumi_token", "saas", "pul-{h:40}", var="PULUMI_ACCESS_TOKEN", rules=("pulumi-api-token",)),
    F("grafana_service_account", "saas", "glsa_{b62:32}_{h:8}", var="GRAFANA_TOKEN",
      rules=("grafana-service-account-token",)),
    F("newrelic_user_key", "saas", "NRAK-{A:27}", var="NEW_RELIC_API_KEY", rules=("new-relic-user-api-key",)),
    F("datadog_api_key", "saas", "{h:32}", var="DATADOG_API_KEY", rules=("generic-api-key", "piifence-password-assignment")),
    F("shopify_access_token", "saas", "shpat_{h:32}", var="SHOPIFY_ACCESS_TOKEN", rules=("shopify-access-token",)),
    F("linear_api_key", "saas", "lin_api_{b62:40}", var="LINEAR_API_KEY", rules=("linear-api-key",)),
    F("notion_token", "saas", "ntn_{d:11}{b62:35}", var="NOTION_TOKEN", rules=("notion-api-token",)),
    F("postman_api_key", "saas", "PMAK-{h:24}-{h:34}", var="POSTMAN_API_KEY", rules=("postman-api-token",)),
    F("sentry_user_token", "saas", "sntryu_{h:64}", var="SENTRY_AUTH_TOKEN", rules=("sentry-user-token",)),
    F("supabase_pat", "saas", "sbp_{h:40}", var="SUPABASE_ACCESS_TOKEN", rules=("piifence-supabase-pat",)),
    F("planetscale_password", "saas", "pscale_pw_{b64url:43}", var="PLANETSCALE_PASSWORD",
      rules=("planetscale-password",)),
    F("okta_token", "saas", "00{b64url:40}", var="OKTA_API_TOKEN", rules=("okta-access-token",)),
    F("onepassword_service_token", "saas", "ops_eyJ{b64:260}", var="OP_SERVICE_ACCOUNT_TOKEN",
      rules=("1password-service-account-token",)),
    F("age_secret_key", "saas", "AGE-SECRET-KEY-1{BECH:58}", var="AGE_KEY", rules=("age-secret-key",)),
    # structural
    F("pem_rsa_private_key", "structural", build=_pem("RSA"), rules=("private-key",), multiline=True),
    F("pem_ec_private_key", "structural", build=_pem("EC"), rules=("private-key",), multiline=True),
    F("pem_openssh_private_key", "structural", build=_pem("OPENSSH"), rules=("private-key",), multiline=True),
    F("pem_pkcs8_private_key", "structural", build=_pem(""), rules=("private-key",), multiline=True),
    F("pem_encrypted_private_key", "structural", build=_pem("ENCRYPTED"), rules=("private-key",), multiline=True),
    F("pgp_private_key_block", "structural", build=_pem("PGP"), rules=("private-key",), multiline=True),
    F("jwt", "structural", "eyJ{b62:30}.eyJ{b64url:60}.{b64url:43}", var="ACCESS_TOKEN", rules=("jwt", "piifence-jwt")),
    F("basic_auth_header", "structural", build=_basic_auth, rules=("piifence-authorization-header",)),
    F("bearer_opaque", "structural", build=_bearer, rules=("piifence-authorization-header",)),
    F("url_postgres", "structural", build=_url("postgres://", "app", 18, "db.internal:5432/app"),
      var="DATABASE_URL", rules=("piifence-url-credentials",)),
    F("url_mysql", "structural", build=_url("mysql://", "root", 14, "10.0.0.5:3306/shop"),
      var="MYSQL_URL", rules=("piifence-url-credentials",)),
    F("url_mongodb_srv", "structural", build=_url("mongodb+srv://", "svc", 20, "cluster0.abcde.mongodb.net/db"),
      var="MONGO_URI", rules=("piifence-url-credentials",)),
    F("url_redis_no_user", "structural", build=_url("redis://", "", 24, "cache.internal:6379/0"), var="REDIS_URL", rules=("piifence-url-credentials",)),
    F("url_amqp", "structural", build=_url("amqp://", "worker", 16, "mq.internal:5672/"),
      var="AMQP_URL", rules=("piifence-url-credentials",)),
    F("url_git_https_token", "structural", build=_git_https_token, var="GIT_REMOTE",
      rules=("github-pat", "piifence-url-credentials")),
    F("sqlserver_conn_string", "structural", build=_sqlserver, var="SQL_CONN", rules=("piifence-password-assignment",)),
    F("jdbc_password", "structural", build=_jdbc, var="JDBC_URL", rules=("piifence-password-assignment",)),
    F("kubeconfig_token", "structural", build=_kube_token),
    F("docker_config_auth", "structural", build=_docker_auth),
    F("netrc_password", "structural", build=_netrc, rules=("piifence-netrc-password",)),
    # generic
    F("password_human", "generic", "{pw:14}", var="DB_PASSWORD", rules=("piifence-password-assignment",)),
    F("password_with_quote_and_backslash", "generic", build=_pw_quote_backslash, var="DB_PASSWORD", rules=("piifence-password-assignment",)),
    F("password_with_dollar_and_space", "generic", build=_pw_dollar_space, var="ADMIN_PASSWORD"),
    F("hex32_with_keyword", "generic", "{h:32}", var="API_KEY", rules=("generic-api-key", "piifence-password-assignment")),
    F("hex64_with_keyword", "generic", "{h:64}", var="SIGNING_SECRET", rules=("generic-api-key", "piifence-password-assignment")),
    # generic-api-key only allows [\w.=-]; the piifence assignment rule also accepts + and /.
    F("base64_40_with_keyword", "generic", "{b64:40}", var="CLIENT_SECRET", rules=("piifence-password-assignment",)),
    F("hex32_bare_no_keyword", "generic", build=_bare_hex),
]

BY_ID = {f.id: f for f in FORMATS}
assert len(BY_ID) == len(FORMATS), "duplicate format id"

# Formats run through every context (the rest run through three).
CORE = [
    "github_pat_classic", "aws_access_key_id", "aws_secret_access_key", "anthropic_api_key",
    "openai_project_key", "stripe_live_secret", "slack_bot_token", "pem_rsa_private_key",
    "jwt", "url_postgres", "password_human", "hex32_with_keyword",
]

# Formats packed together into one .env for the many_in_one_block context.
MANY = [
    "github_pat_classic", "aws_access_key_id", "aws_secret_access_key", "gcp_api_key",
    "anthropic_api_key", "stripe_live_secret", "slack_bot_token", "npm_token",
    "sendgrid_key", "url_postgres", "jwt", "password_human",
]
