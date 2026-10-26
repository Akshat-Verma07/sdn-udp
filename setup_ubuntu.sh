#!/usr/bin/env bash
# setup_ubuntu.sh - install everything needed on a fresh Ubuntu VM.
# Usage: bash setup_ubuntu.sh
set -e

sudo apt-get update
sudo apt-get install -y mininet openvswitch-switch python3-pip python3-venv git

# Ryu needs an older eventlet to work; a virtualenv keeps it away from the
# system Python.  (Ryu is unmaintained, so on very new Ubuntu/Python versions
# you may need Python 3.9/3.10 - see README "Troubleshooting".)
python3 -m venv ~/ryu-venv
source ~/ryu-venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install "eventlet==0.30.2" ryu

echo
echo "Setup finished. Next:"
echo "  source ~/ryu-venv/bin/activate && ryu-manager controller/sdn_controller.py"
echo "  (second terminal)  sudo python3 topology/diamond_topo.py --transfer"
