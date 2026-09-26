#!/usr/bin/env bash
# Runs the reference implementation drills inside a live AMD SEV-SNP guest on Google Cloud and
# brings the evidence back. Creates the VM, copies impl/, runs run_drills.py --tee sev-snp with a
# report burst, copies the evidence directory back, deletes the VM. Idempotent per STAMP.
#
#   scripts/gcp-snp-drill.sh [PROJECT] [ZONE]
#
# Cost: one n2d-standard-2 confidential VM for ~15 minutes.
set -euo pipefail
PROJECT="${1:-rats-probe}"
ZONE="${2:-us-central1-c}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
NAME="tacra-est-snp-$(echo "$STAMP" | tr -d 'TZ' | cut -c3-12)"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$HERE/evidence/${STAMP}-gcp-sev-snp"
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

echo "== create $NAME ($ZONE, n2d-standard-2, SEV_SNP)"
gcloud compute instances create "$NAME" --project="$PROJECT" --zone="$ZONE" \
  --machine-type=n2d-standard-2 --min-cpu-platform="AMD Milan" \
  --confidential-compute-type=SEV_SNP --maintenance-policy=TERMINATE \
  --image-family=ubuntu-2404-lts-amd64 --image-project=ubuntu-os-cloud \
  --boot-disk-size=20GB --labels=purpose=tacra-est,stamp="$(echo "$STAMP" | tr -d 'TZ')" \
  --metadata=enable-oslogin=TRUE >/dev/null
trap 'echo "== delete $NAME"; gcloud compute instances delete "$NAME" --project="$PROJECT" --zone="$ZONE" --quiet >/dev/null 2>&1 || true' EXIT

echo "== wait for ssh"
for i in $(seq 1 30); do
  if gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command='true' >/dev/null 2>&1; then break; fi
  sleep 10
done

echo "== provision (python venv, cryptography, pyhpke, sev-guest module)"
gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command='
set -e
sudo apt-get update -qq >/dev/null
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3-venv python3-pip openssl >/dev/null
sudo modprobe sev-guest 2>/dev/null || true
if [ ! -e /dev/sev-guest ]; then sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq linux-modules-extra-$(uname -r) >/dev/null; sudo modprobe sev-guest || true; fi
ls -l /dev/sev-guest
python3 -m venv ~/venv && ~/venv/bin/pip install -q --upgrade pip && ~/venv/bin/pip install -q cryptography pyhpke
uname -a; dmesg 2>/dev/null | grep -i -E "sev|snp" | head -5 || true
'

echo "== copy impl/"
gcloud compute scp --recurse "$HERE/impl" "$NAME:~/impl" --project="$PROJECT" --zone="$ZONE" >/dev/null

echo "== run drills (as root: /dev/sev-guest), burst of 200 reports"
gcloud compute ssh "$NAME" --project="$PROJECT" --zone="$ZONE" --command="
set -e
sudo mkdir -p /root/evidence
sudo ~/venv/bin/python3 ~/impl/run_drills.py --tee sev-snp --out /root/evidence/${STAMP} --burst 200 2>&1 | tail -30
sudo sh -c 'cd /root/evidence/${STAMP} && uname -a > kernel.txt && (dmesg 2>/dev/null | grep -i -E \"sev|snp\" > dmesg-sev.txt || true) && (curl -s -H Metadata-Flavor:Google http://metadata.google.internal/computeMetadata/v1/instance/machine-type > machine-type.txt || true) && sha256sum * > sha256sums.txt'
sudo chmod -R a+r /root/evidence/${STAMP}; sudo cp -r /root/evidence/${STAMP} ~/evidence-out
"

echo "== copy evidence back to $OUT"
mkdir -p "$OUT"
gcloud compute scp --recurse "$NAME:~/evidence-out/*" "$OUT/" --project="$PROJECT" --zone="$ZONE" >/dev/null
ls -la "$OUT"
echo "== done; VM is deleted on exit"
