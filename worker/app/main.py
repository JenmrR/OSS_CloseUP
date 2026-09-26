"""worker 자리표시.

2주차에 여기서 ScanRun(status=queued)을 가져와 검사하는 루프를 구현한다.
지금은 컨테이너가 떠 있는 상태만 유지하고, 검사는 run_sample_scan.sh 로 수동 실행한다.
"""
import signal
import subprocess
import sys
import time

running = True


def stop(*_):
    global running
    running = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

for cmd in (["trivy", "--version"], ["osv-scanner", "--version"], ["syft", "version"]):
    lines = subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()
    ver = next((l.strip() for l in lines if "ersion" in l), "?")
    print("[worker]", cmd[0], "->", ver, flush=True)
print("[worker] ready (ScanRun 폴링은 2주차 구현 예정)", flush=True)

while running:
    time.sleep(1)
sys.exit(0)
