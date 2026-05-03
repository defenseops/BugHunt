#!/usr/bin/env bash
# PentraScan Smoke Test
# Usage: bash docs/smoke_test.sh [BASE_URL]
# Example: bash docs/smoke_test.sh http://localhost:8000

set -euo pipefail

BASE="${1:-http://localhost:8000}"
API="$BASE/api/v1"
PASS=0
FAIL=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "${GREEN}  ✓${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}  ✗${NC} $1"; ((FAIL++)); }
info() { echo -e "${YELLOW}  ▶${NC} $1"; }

expect_status() {
  local label="$1" expected="$2"
  shift 2
  local got
  got=$(curl -s -o /dev/null -w "%{http_code}" "$@")
  if [[ "$got" == "$expected" ]]; then
    ok "$label (HTTP $got)"
  else
    fail "$label — expected $expected, got $got"
  fi
}

expect_field() {
  local label="$1" field="$2"
  shift 2
  local body
  body=$(curl -s "$@")
  if echo "$body" | grep -q "\"$field\""; then
    ok "$label (field '$field' present)"
  else
    fail "$label — field '$field' missing. Body: $body"
  fi
}

# ── 1. Health ──────────────────────────────────────────────────────────────
echo ""
info "1. Health check"
expect_status "GET /health" 200 "$BASE/health"

# ── 2. Register ────────────────────────────────────────────────────────────
echo ""
info "2. Auth — Register"
EMAIL="smoketest_$(date +%s)@test.com"
REG=$(curl -s -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"Smoke1234\",\"full_name\":\"Smoke Test\"}")

if echo "$REG" | grep -q '"access_token"'; then
  ok "POST /auth/register"
  TOKEN=$(echo "$REG" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
  REFRESH=$(echo "$REG" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
else
  fail "POST /auth/register — $REG"
  TOKEN=""
  REFRESH=""
fi

# Duplicate email → 409
expect_status "POST /auth/register duplicate → 409" 409 \
  -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"Smoke1234\",\"full_name\":\"Dup\"}"

# ── 3. Login ───────────────────────────────────────────────────────────────
echo ""
info "3. Auth — Login"
LOGIN=$(curl -s -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"Smoke1234\"}")

if echo "$LOGIN" | grep -q '"access_token"'; then
  ok "POST /auth/login"
  TOKEN=$(echo "$LOGIN" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
  REFRESH=$(echo "$LOGIN" | grep -o '"refresh_token":"[^"]*"' | cut -d'"' -f4)
else
  fail "POST /auth/login — $LOGIN"
fi

# Bad password → 401
expect_status "POST /auth/login bad password → 401" 401 \
  -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"wrongpass\"}"

# ── 4. /me ─────────────────────────────────────────────────────────────────
echo ""
info "4. Users — /me"
AUTH_H="Authorization: Bearer $TOKEN"
expect_field "GET /users/me" "email" "$API/users/me" -H "$AUTH_H"
expect_status "GET /users/me no token → 401" 401 "$API/users/me"

# ── 5. Refresh ─────────────────────────────────────────────────────────────
echo ""
info "5. Auth — Refresh"
REFRESH_RESP=$(curl -s -X POST "$API/auth/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\":\"$REFRESH\"}")
if echo "$REFRESH_RESP" | grep -q '"access_token"'; then
  ok "POST /auth/refresh"
  TOKEN=$(echo "$REFRESH_RESP" | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)
  AUTH_H="Authorization: Bearer $TOKEN"
else
  fail "POST /auth/refresh — $REFRESH_RESP"
fi

# ── 6. Scans CRUD ──────────────────────────────────────────────────────────
echo ""
info "6. Scans"
expect_field "GET /scans" "items" "$API/scans" -H "$AUTH_H"

# Create scan
SCAN=$(curl -s -X POST "$API/scans" \
  -H "Content-Type: application/json" \
  -H "$AUTH_H" \
  -d '{"target":"192.168.1.1","scan_type":"port"}')
if echo "$SCAN" | grep -q '"id"'; then
  ok "POST /scans"
  SCAN_ID=$(echo "$SCAN" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
else
  fail "POST /scans — $SCAN"
  SCAN_ID=""
fi

# Invalid target → 422
expect_status "POST /scans bad target → 422" 422 \
  -X POST "$API/scans" \
  -H "Content-Type: application/json" \
  -H "$AUTH_H" \
  -d '{"target":"not-valid-!!","scan_type":"port"}'

if [[ -n "$SCAN_ID" ]]; then
  expect_field "GET /scans/$SCAN_ID" "target" "$API/scans/$SCAN_ID" -H "$AUTH_H"
  expect_status "GET /scans/bad-uuid → 422" 422 "$API/scans/not-a-uuid" -H "$AUTH_H"
fi

# Free limit: create 2 more scans (already have 1)
for i in 2 3; do
  curl -s -X POST "$API/scans" \
    -H "Content-Type: application/json" \
    -H "$AUTH_H" \
    -d "{\"target\":\"10.0.0.$i\",\"scan_type\":\"port\"}" > /dev/null
done

LIMIT_RESP=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "$API/scans" \
  -H "Content-Type: application/json" \
  -H "$AUTH_H" \
  -d '{"target":"10.0.0.99","scan_type":"port"}')
if [[ "$LIMIT_RESP" == "402" ]]; then
  ok "POST /scans free limit → 402"
else
  fail "POST /scans free limit — expected 402, got $LIMIT_RESP"
fi

# ── 7. Reports ─────────────────────────────────────────────────────────────
echo ""
info "7. Reports"
if [[ -n "$SCAN_ID" ]]; then
  # Scan is pending/running — should return 409
  expect_status "POST /reports/$SCAN_ID/generate (not completed) → 409" 409 \
    -X POST "$API/reports/$SCAN_ID/generate" \
    -H "Content-Type: application/json" \
    -H "$AUTH_H" \
    -d '{"lang":"ru"}'

  expect_status "GET /reports/$SCAN_ID/download (no report) → 404" 404 \
    "$API/reports/$SCAN_ID/download" -H "$AUTH_H"
fi

# ── 8. Billing status ──────────────────────────────────────────────────────
echo ""
info "8. Billing"
expect_field "GET /billing/status" "plan" "$API/billing/status" -H "$AUTH_H"

# ── 9. Admin (should be 403 for regular user) ──────────────────────────────
echo ""
info "9. Admin (403 for non-admin)"
expect_status "GET /admin/users → 403" 403 "$API/admin/users" -H "$AUTH_H"
expect_status "GET /admin/stats → 403" 403 "$API/admin/stats" -H "$AUTH_H"

# ── 10. Logout ─────────────────────────────────────────────────────────────
echo ""
info "10. Auth — Logout"
expect_status "POST /auth/logout" 204 \
  -X POST "$API/auth/logout" -H "$AUTH_H"

# Token should be blacklisted after logout
expect_status "GET /users/me after logout → 401" 401 "$API/users/me" -H "$AUTH_H"

# ── Summary ────────────────────────────────────────────────────────────────
echo ""
echo "─────────────────────────────────────"
echo -e "  ${GREEN}PASS: $PASS${NC}   ${RED}FAIL: $FAIL${NC}"
echo "─────────────────────────────────────"
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
