#!/usr/bin/env bash
# Genera el .env del dashboard de forma interactiva.
set -e
echo "=== Setup Vectus SOC Dashboard ==="
read -p "Email del primer admin: " ADMIN
read -p "SMTP host (enter para omitir y loguear el OTP): " SMTPH
read -p "SMTP email: " SMTPE
read -sp "SMTP password (app password): " SMTPP; echo
JWT=$(python3 -c "import secrets;print(secrets.token_hex(32))")
cat > .env << EOL
APP_PORT=8005
JWT_HOURS=8
COOKIE_SECURE=false
OTP_TTL_MIN=10
ADMIN_EMAIL=${ADMIN}
ENGINE_DB_PATH=/engine-data/vectus.db
SMTP_HOST=${SMTPH}
SMTP_PORT=587
SMTP_EMAIL=${SMTPE}
SMTP_PASSWORD=${SMTPP}
JWT_SECRET=${JWT}
EOL
echo ".env generado. Levantá con: docker compose up -d --build"
