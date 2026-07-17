# WIDPS - Phase 1

## Build
    cargo build --release

## Run (must be run from the project root so config/ paths resolve)
    sudo ./target/release/widps

## Prerequisites
    sudo airmon-ng start wlan1
    sudo ip link set wlan1mon up

## Config
- config/whitelist.toml - your known-good APs (edit before demo)
- config/oui.csv - vendor prefixes (replace with full IEEE list for production accuracy)

## Output
- Live console alerts
- widps_alerts.jsonl - structured log for your report

## Demo (own test AP only)
    sudo aireplay-ng --deauth 20 -a <test_AP_BSSID> wlan1mon