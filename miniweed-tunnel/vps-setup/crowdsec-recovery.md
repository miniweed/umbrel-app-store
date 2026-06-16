# CrowdSec recovery runbook (VPS)

Use this when `--with-crowdsec` was enabled and the VPS loses connectivity or blocks legitimate traffic.

## 1) Emergency unban and temporary stop

```bash
sudo cscli decisions delete --all
sudo systemctl stop crowdsec-firewall-bouncer crowdsec
```

## 2) Verify firewall baseline still allows tunnel traffic

```bash
sudo iptables -S INPUT | grep -- "--dport 22"
sudo iptables -S INPUT | grep -- "--dport 443"
sudo iptables -S INPUT | grep -- "--dport 51820"
```

## 3) Disable CrowdSec bouncer if repeated lockouts

```bash
sudo systemctl disable crowdsec-firewall-bouncer
sudo systemctl stop crowdsec-firewall-bouncer

# optional: clear CrowdSec iptables chains to avoid residual blocks
sudo iptables-save | grep -qi crowdsec && sudo iptables-save > /root/iptables.before.crowdsec.cleanup.rules
sudo iptables -S | grep -E "CROWDSEC|crowdsec" || true
```

## 4) Re-enable with logs once stable

```bash
sudo systemctl enable crowdsec crowdsec-firewall-bouncer
sudo systemctl restart crowdsec crowdsec-firewall-bouncer
sudo journalctl -u crowdsec -u crowdsec-firewall-bouncer -n 100 --no-pager
sudo cscli lapi status
sudo cscli bouncers list
sudo iptables-save | grep -i crowdsec
```

## 5) Smoke check

```bash
sudo bash miniweed-tunnel/vps-setup/crowdsec-smoke.sh
```
