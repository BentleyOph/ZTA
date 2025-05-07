"""
Generate synthetic “Access Request” events that match the on‑disk schema and
feed them to a Flask ingest endpoint in real time.
"""

import random, time, argparse, requests, json
from datetime import datetime, timedelta
from uuid import uuid4
from faker import Faker

fake = Faker()


API_URL        = "http://127.0.0.1:5000/simulate_ml"
EVENTS_PER_SEC = 1.5
ANOMALY_RATIO  = 0.15

USERS = [
    "b51b2e35-ee9d-4e6a-9118-8c288582219d",
    "4b8c00e9-6e1e-4d08-9fd6-482309bab5e7",
    "1e533b58-cc7d-4ad7-8ff8-6b76bb04d589",
]

RESOURCES = [
    "Resource 1",
    "Resource 2",
    "Resource 3",
]

DEVICE_TYPES = ["Desktop", "Laptop", "Mobile"]

OS_CHOICES = ["Win32", "Mac OS", "Linux", "Android_14"]

VENDORS = [
    "Microsoft Corporation",
    "Apple Inc.",
    "Samsung Electronics",
    "Canonical Ltd.",
]

# ---------------------------------------------------------------------------#
# 2.  Event builders
# ---------------------------------------------------------------------------#
def make_uuid():
    """Return a monotonically increasing integer ID (simple counter)."""
    make_uuid.counter += 1
    return make_uuid.counter
make_uuid.counter = 200  # start near your sample ID (=243 later)

def random_browser():
    """Return a realistic User‑Agent string."""
    return fake.user_agent()

def base_event(user: str) -> dict:
    """Create one ‘normal’ access request event."""
    return {
        "ID": make_uuid(),
        "user_id": user,
        "intent": "Access Request",
        "resource_requested": random.choice(RESOURCES),
        # Same format as sample: 2025-05-07 02:18:21
        "access_request_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "public_ip_address": fake.ipv4_public(),
        "location": "Nairobi/KE",
        "device_type": random.choice(DEVICE_TYPES),
        "browser": random_browser(),
        "device_mac": fake.mac_address(),
        "device_vendor": random.choice(VENDORS),
        "device_OS": random.choice(OS_CHOICES),
    }

def mutate_to_anomaly(event: dict) -> dict:
    """Inject fields that should look suspicious to the iForest."""
    event = event.copy()
    # Impossible travel: same user, far‑away geo within minutes
    event["access_request_time"] = (
        datetime.now() + timedelta(hours=10)
    ).strftime("%Y-%m-%d %H:%M:%S")
    event["location"] = "Seoul/KR"
    event["public_ip_address"] = fake.ipv4(network=False, private=False)
    # Sketchy old OS and device vendor
    event["device_OS"] = "Windows_XP"
    event["device_vendor"] = "Unknown Vendor"
    return event

# ---------------------------------------------------------------------------#
# 3.  Main loop
# ---------------------------------------------------------------------------#
def main(rps: float, anomaly_ratio: float):
    period = 1.0 / rps
    while True:
        user   = random.choice(USERS)
        record = base_event(user)

        if random.random() < anomaly_ratio:
            record = mutate_to_anomaly(record)

        try:
            resp = requests.post(API_URL, json=record, timeout=1.5)
            resp.raise_for_status()
            score = resp.json().get("anomaly_score", "?.?")
            print(f"{record['ID']:>4}  {record['location']:<9} "
                  f"{record['device_OS']:<10}  →  score={score:.3f}")
        except requests.RequestException as err:
            print("POST failed:", err)

        time.sleep(period)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rps",   type=float, default=EVENTS_PER_SEC,
                    help="events per second (default 1.5)")
    ap.add_argument("--ratio", type=float, default=ANOMALY_RATIO,
                    help="fraction of events that are anomalous (default 0.15)")
    args = ap.parse_args()
    main(rps=args.rps, anomaly_ratio=args.ratio)
