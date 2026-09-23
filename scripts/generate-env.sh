#!/usr/bin/env bash
# Create .env.hermes from .env.hermes.example with freshly generated secrets.
# Refuses to overwrite an existing .env.hermes. Provider credentials are left
# blank — add at least one before starting the stack.
set -euo pipefail

cd "$(dirname "$0")/.."

TEMPLATE=.env.hermes.example
TARGET=.env.hermes

if [[ -e "$TARGET" ]]; then
  echo "Error: $TARGET already exists; refusing to overwrite it." >&2
  echo "Existing secrets protect existing receipts — edit it by hand instead." >&2
  exit 1
fi
command -v openssl >/dev/null || { echo "Error: openssl is required." >&2; exit 1; }

umask 077
cp "$TEMPLATE" "$TARGET"
for var in HERMES_SIGNING_KEY HERMES_VAULT_KEY HERMES_GATEWAY_KEYSTORE_PASSPHRASE \
           HERMES_ADMIN_TOKEN HERMES_API_KEY; do
  sed -i "s|^${var}=\$|${var}=$(openssl rand -hex 32)|" "$TARGET"
done
chmod 600 "$TARGET"

echo "Wrote $TARGET (mode 600) with generated secrets."
echo "Next: set at least one provider credential in $TARGET, e.g. HERMES_OPENAI_API_KEY."
