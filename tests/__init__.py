import os

# Test-only passphrase (non-interactive). Never use an environment passphrase in production.
os.environ.setdefault("SENTINELA_PASSPHRASE", "test-passphrase-only-for-unit-tests")
