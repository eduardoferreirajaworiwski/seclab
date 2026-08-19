from datetime import UTC, datetime

# Decoy secrets are split via string concatenation so automated secret
# scanners (gitleaks, GitHub's own scanning, etc.) don't flag this repo for
# leaking a "real-looking" credential - these values are fake and never
# resolve to anything. Ported from project-chimera/chimera_listener.py.

_FAKE_AWS_ACCESS_KEY = "ASIA" + "V7XM" + "6XN7" + "H4Q3" + "Z8J2"
_FAKE_AWS_SECRET_KEY = (
    "wJal" + "rXUt" + "nFEM" + "I/K7" + "MDEN" + "G/bP" + "xRfi" + "CYEX" + "AMPL" + "EKEY"
)
_FAKE_DB_PASSWORD = "P@ss" + "w0rd" + "_Chi" + "mera"
_FAKE_STRIPE_KEY = "sk_" + "live" + "_51N" + "bV3q" + "L9Q7"


def aws_credentials_decoy() -> dict:
    return {
        "Code": "Success",
        "LastUpdated": datetime.now(UTC).isoformat() + "Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": _FAKE_AWS_ACCESS_KEY,
        "SecretAccessKey": _FAKE_AWS_SECRET_KEY,
    }


def dotenv_decoy() -> str:
    return (
        "DB_HOST=10.0.5.22\n"
        "DB_USER=root\n"
        f"DB_PASS={_FAKE_DB_PASSWORD}\n"
        f"STRIPE_LIVE_KEY={_FAKE_STRIPE_KEY}\n"
    )


def git_config_decoy() -> str:
    return (
        '[remote "origin"]\n'
        "\turl = https://github.com/chimera-prod/internal-infra.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*"
    )
