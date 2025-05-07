"""
Generate synthetic “Access Request” events that match the on‑disk schema and
feed them to a Flask ingest endpoint in real time.
"""

import random, time, argparse, requests, json
from datetime import datetime, timedelta
from uuid import uuid4
from faker import Faker

fake = Faker()


API_ML_URL        = "http://127.0.0.1:5000/simulate_ml"
ACCESS_REQUEST_URL = "http://127.0.1:5000/receive-access-request"
EVENTS_PER_SEC = 1.5
ANOMALY_RATIO  = 0.15

USERS = [
    "b51b2e35-ee9d-4e6a-9118-8c288582219d", #test approver
    "da200b79-3bc2-40c9-b0cb-61ad4a71f039",#phember policy admin
    "e026b331-5c21-4e79-a7c9-220e7800bfbb",#bento policy admin
    "51d70266-13ed-445d-9d1a-0185b9a35fec",#pree approver
    "d2bcb609-de65-4947-ab2a-c68536ddfc7b" # tess approver
]

RESOURCES = [
    "Resource 1",
    "Resource 2",
]

DEVICE_TYPES = ["Desktop", "Laptop", "Mobile"]

OS_CHOICES = ["Win32", "Mac OS", "Linux", "Android_14"]

VENDORS = [
    "Microsoft Corporation",
    "Apple Inc.",
    "Samsung Electronics",
    "Canonical Ltd.",
]
LOCATIONS = [
    "Nairobi/KE",
    "Kisumu/KE",
    "Mombasa/KE",
]

RANDOM_LOCATIONS_WORLDWID = [
    "New York/US",
    "Tokyo/JP",
    "London/GB",
    "Berlin/DE",
    "Paris/FR",
    "Sydney/AU",
    "Seoul/KR",
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

def base_event_ml(user: str) -> dict:
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




def base_event_access(user: str) -> dict:
    return {
        "ID": make_uuid(),
        'userId': user,
        'intent': 'Access Request',
        'resource': random.choice(RESOURCES),
        'access_request_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'public_ip': fake.ipv4_public(),
        'location': random.choice(LOCATIONS),
        'deviceType': random.choice(DEVICE_TYPES),
        'userAgent': random_browser(),
        'device_mac': fake.mac_address(),
        'device_vendor': random.choice(VENDORS),
        'operatingSystem': random.choice(OS_CHOICES),
    }

def mutate_to_anomaly_ml(event: dict) -> dict:
    """Inject fields that should look suspicious to the iForest."""
    event = event.copy()
    # Impossible travel: same user, far‑away geo within minutes
    event["access_request_time"] = (
        datetime.now() + timedelta(hours=10)
    ).strftime("%Y-%m-%d %H:%M:%S")
    print(event["access_request_time"])
    event["location"] = random.choice(RANDOM_LOCATIONS_WORLDWID)
    event["public_ip_address"] = fake.ipv4(network=False, private=False)
    # Sketchy old OS and device vendor
    event["device_OS"] = "Windows_XP"
    event["device_vendor"] = "Unknown Vendor"
    return event


def mutate_to_anomaly(event: dict) -> dict:
    """Inject fields that should look suspicious to the iForest."""
    event = event.copy()
    # Impossible travel: same user, far‑away geo within minutes
    event["access_request_time"] = (
        datetime.now() + timedelta(hours=10)
    ).strftime("%Y-%m-%d %H:%M:%S")
    event["location"] = "Seoul/KR"
    event["public_ip"] = fake.ipv4(network=False, private=False)
    # Sketchy old OS and device vendor
    event["operatingSystem"] = "Windows_XP"
    event["device_vendor"] = "Unknown Vendor"
    return event


# ---------------------------------------------------------------------------#
# 3.  Main loop
# ---------------------------------------------------------------------------#
def main(rps: float, anomaly_ratio: float ,ml: bool = True) -> None:
    period = 1.0 / rps
    while True:
        user   = random.choice(USERS)
        record = base_event_access(user)

        if ml:
            record = base_event_ml(user)

        if random.random() < anomaly_ratio:
            if ml:
                record = mutate_to_anomaly_ml(record)
            else:
                record = mutate_to_anomaly(record)
            

        try:
            if ml:
                resp = requests.post(API_ML_URL, json=record, timeout=1.5)
                resp.raise_for_status()
                score = resp.json().get("anomaly_score", "?.?")
                prediction = resp.json().get("prediction", "?.?")
            else:
                resp = requests.post(ACCESS_REQUEST_URL, json=record, timeout=1.5)
                resp.raise_for_status()
                score = resp.json().get("verdict", "?.?")

            if ml:
                print(f"{record['ID']:>4}  {record['location']:<9} "
                      f"{record['device_OS']:<10}  →  score={score:.3f} prediction ={prediction}")
            else:
                print(f"{record['ID']:>4}  {record['location']:<9} "
                f"{record['operatingSystem']:<10}  →  verdict={score:.3f}")
        except requests.RequestException as err:
            print("POST failed:", err)

        time.sleep(period)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rps",   type=float, default=EVENTS_PER_SEC,
                    help="events per second (default 1.5)")
    ap.add_argument("--ratio", type=float, default=ANOMALY_RATIO,
                    help="fraction of events that are anomalous (default 0.15)")
    ap.add_argument("--ml",    action="store_true",
                    help="test ML endpoint directly")
    args = ap.parse_args()
    main(rps=args.rps, anomaly_ratio=args.ratio)
