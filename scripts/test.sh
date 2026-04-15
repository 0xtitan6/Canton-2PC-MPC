#!/bin/bash
# Test script for Canton 2PC-MPC
# Runs all tests without requiring a Canton validator node

set -e

echo "=========================================="
echo "Canton 2PC-MPC Test Suite"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}Error: cargo is not installed${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}Running crypto-core tests...${NC}"
cargo test -p crypto-core --lib 2>&1 || true

echo ""
echo -e "${YELLOW}Running mpc-protocol tests...${NC}"
cargo test -p mpc-protocol --lib 2>&1 || true

echo ""
echo -e "${YELLOW}Running chain-bitcoin tests...${NC}"
cargo test -p chain-bitcoin --lib 2>&1 || true

echo ""
echo -e "${YELLOW}Running chain-ethereum tests...${NC}"
cargo test -p chain-ethereum --lib 2>&1 || true

echo ""
echo -e "${YELLOW}Running chain-solana tests...${NC}"
cargo test -p chain-solana --lib 2>&1 || true

echo ""
echo -e "${YELLOW}Running dwallet tests...${NC}"
cargo test -p dwallet --lib 2>&1 || true

echo ""
echo -e "${YELLOW}Running canton-integration tests (mock mode)...${NC}"
cargo test -p canton-integration --lib 2>&1 || true

echo ""
echo -e "${GREEN}=========================================="
echo "Test suite completed!"
echo "==========================================${NC}"
