"""
Generate synthetic “Access Request” events that match the on‑disk schema and
feed them to a Flask ingest endpoint in real time.
"""

import random
import time
import argparse
import requests
import json
from datetime import datetime, timedelta
from uuid import uuid4
from faker import Faker

fake = Faker()


API_ML_URL = "http://127.0.0.1:5000/simulate_ml"
ACCESS_REQUEST_URL = "http://127.0.1:5000/receive-access-request"
EVENTS_PER_SEC = 1.5
ANOMALY_RATIO = 0.15

USERS = [
    "b51b2e35-ee9d-4e6a-9118-8c288582219d",  # "test" Branch Manager
    # "da200b79-3bc2-40c9-b0cb-61ad4a71f039",  # phember Security Analyst (Excluded)
    "e026b331-5c21-4e79-a7c9-220e7800bfbb",  # bento Policy Administrator
    # "51d70266-13ed-445d-9d1a-0185b9a35fec",  # pree Security Analyst (Excluded)
    # "7e9e36c3-19c3-4a88-94e6-b3167b8e1b43", # viwer Security Analyst (Excluded)
    "d2bcb609-de65-4947-ab2a-c68536ddfc7b",  # tess Loan Officer
    "f7c71c7e-88a1-4de5-be25-aa87bcb1331a"   # Customer Service
]

USER_TO_ROLE_MAPPING = {
    "b51b2e35-ee9d-4e6a-9118-8c288582219d": "Branch Manager",
    "e026b331-5c21-4e79-a7c9-220e7800bfbb": "Security Administrator", # bento Policy Administrator
    "d2bcb609-de65-4947-ab2a-c68536ddfc7b": "Loan Officer",
    "f7c71c7e-88a1-4de5-be25-aa87bcb1331a": "Customer Service"
}

# Update USERS to only include those in the mapping
USERS = list(USER_TO_ROLE_MAPPING.keys())

USER_ROLES = [
    "Branch Manager",
    "Loan Officer",
    "Security Administrator",
    "Customer Service"

]

RESOURCES = [
    "Resource 1",
    "Resource 2",
    "Resource 3",
]


DEVICE_TYPES = ["Desktop", "Laptop", "Mobile"]

OS_CHOICES = ["Win32", "Mac OS", "Android_14"]

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


def random_working_hour_time() -> datetime:
    """Generate a random datetime object within working hours (6 AM to 8 PM)
    over the last 5 days."""
    now = datetime.now()
    # Randomly choose a day from the last 5 days (0 to 4 days ago)
    days_ago = random.randint(0, 29)
    target_date = now - timedelta(days=days_ago)
    
    hour = random.randint(6, 19) # 6 AM to 7:59:59 PM, effectively up to 8 PM
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return target_date.replace(hour=hour, minute=minute, second=second, microsecond=0)


def base_event_ml(user: str) -> dict:
    """Create one ‘normal’ access request event."""
    
    user_role_for_event = USER_TO_ROLE_MAPPING[user]
    if user_role_for_event in ["Security Administrator", "Branch Manager"]:
        resource = random.choice(RESOURCES)
    elif user_role_for_event == "Loan Officer": # Changed from 'in ["Loan Officer"]' for clarity
        resource = RESOURCES[1]
    elif user_role_for_event == "Customer Service": # Changed from 'in ["Customer Service"]' for clarity
        resource = random.choice([RESOURCES[0], RESOURCES[2]]) # Corrected resource selection



    return {
        "ID": make_uuid(),
        "user_id": user,
        "user_role": user_role_for_event,  # Added user_role
        "intent": "Access Request",
        "resource_requested": resource,
        # Same format as sample: 2025-05-07 02:18:21
        "access_request_time": random_working_hour_time().strftime("%Y-%m-%d %H:%M:%S"),
        "public_ip_address": fake.ipv4_public(),
        "location": "Nairobi/KE",
        "device_type": random.choice(DEVICE_TYPES),
        "browser": random_browser(),
        "device_mac": fake.mac_address(),
        "device_vendor": random.choice(VENDORS),
        "device_OS": random.choice(OS_CHOICES),
    }


def base_event_access(user: str) -> dict:
    
    user_role_for_event = USER_TO_ROLE_MAPPING[user]
    if user_role_for_event in ["Security Administrator", "Branch Manager"]:
        resource = random.choice(RESOURCES)
    elif user_role_for_event == "Loan Officer": # Changed from 'in ["Loan Officer"]' for clarity
        resource = RESOURCES[1]
    elif user_role_for_event == "Customer Service": # Changed from 'in ["Customer Service"]' for clarity
        resource = random.choice([RESOURCES[0], RESOURCES[2]]) # Corrected resource selection


    return {
        "ID": make_uuid(),
        'userId': user,
        'user_role': user_role_for_event,  # Added user_role
        'intent': 'Access Request',
        'resource': resource,
        'access_request_time': random_working_hour_time().strftime('%Y-%m-%d %H:%M:%S'),
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
    anomaly_type = random.choice([
        "impossible_travel",
        "unusual_resource_for_role",
        "after_hours_access",
        "old_os_access"
    ])

    # Ensure user_role is present, though base_event_access should now add it
    user_role = event.get('user_role', 'N/A')
    if user_role == 'N/A' and event['user_id'] in USER_TO_ROLE_MAPPING: # Fallback if not in event
        user_role = USER_TO_ROLE_MAPPING[event['user_id']]

    print(f"Generating anomaly type: {anomaly_type} for user {event['user_id']} (Role: {user_role})")

    if anomaly_type == "impossible_travel":
        event["access_request_time"] = (
            datetime.now() + timedelta(minutes=random.randint(1, 30))
        ).strftime("%Y-%m-%d %H:%M:%S")
        event["location"] = random.choice(RANDOM_LOCATIONS_WORLDWID)
        event["public_ip_address"] = fake.ipv4_public()

    elif anomaly_type == "unusual_resource_for_role":
        if user_role == "Loan Officer":
            # Normally accesses RESOURCES[1]
            event["resource"] = random.choice([r for r in RESOURCES if r != RESOURCES[1]])
        elif user_role == "Customer Service":
            # Normally accesses RESOURCES[0] or RESOURCES[2]
            event["resource"] = RESOURCES[1]
        elif user_role == "Branch Manager":
            # Normally random, make it specific to Loan Officer's typical resource
            event["resource"] = RESOURCES[1]
        elif user_role == "Security Administrator":
            # Normally random, make it specific to Customer Service's typical resource
            event["resource"] = RESOURCES[0]
        else:
            # Fallback: pick a random resource different from current if possible
            current_resource_index = RESOURCES.index(event["resource"]) if event["resource"] in RESOURCES else -1
            possible_resources = [r for i, r in enumerate(RESOURCES) if i != current_resource_index]
            if possible_resources:
                event["resource"] = random.choice(possible_resources)
            # If all else fails, it might remain the same or pick any random one.

    elif anomaly_type == "after_hours_access":
        event["access_request_time"] = datetime.now().replace(hour=random.randint(0, 5), minute=random.randint(0,59), second=random.randint(0,59)).strftime("%Y-%m-%d %H:%M:%S")
        # Resource accessed remains as per base_event_access, anomaly is the time

    elif anomaly_type == "old_os_access":
        event["device_OS"] = random.choice(["Windows XP", "Windows 7"])
        event["device_vendor"] = "Unknown Vendor"
        # Resource accessed remains as per base_event_access, anomaly is the OS/vendor

    return event



def mutate_to_anomaly(event: dict) -> dict:
    """Inject e-banking specific anomalies, adapted for the non-ML context."""
    event = event.copy()
    anomaly_type = random.choice([
        "impossible_travel",
        "unusual_resource_for_role",
        "after_hours_access",
        "old_os_access"
    ])

    # Ensure user_role is present, though base_event_access should now add it
    user_role = event.get('user_role', 'N/A')
    if user_role == 'N/A' and event['userId'] in USER_TO_ROLE_MAPPING: # Fallback if not in event
        user_role = USER_TO_ROLE_MAPPING[event['userId']]

    print(f"Generating anomaly type: {anomaly_type} for user {event['userId']} (Role: {user_role})")

    if anomaly_type == "impossible_travel":
        event["access_request_time"] = (
            datetime.now() + timedelta(minutes=random.randint(1, 30))
        ).strftime("%Y-%m-%d %H:%M:%S")
        event["location"] = random.choice(RANDOM_LOCATIONS_WORLDWID)
        event["public_ip"] = fake.ipv4_public()

    elif anomaly_type == "unusual_resource_for_role":
        if user_role == "Loan Officer":
            # Normally accesses RESOURCES[1]
            event["resource"] = random.choice([r for r in RESOURCES if r != RESOURCES[1]])
        elif user_role == "Customer Service":
            # Normally accesses RESOURCES[0] or RESOURCES[2]
            event["resource"] = RESOURCES[1]
        elif user_role == "Branch Manager":
            # Normally random, make it specific to Loan Officer's typical resource
            event["resource"] = RESOURCES[1]
        elif user_role == "Security Administrator":
            # Normally random, make it specific to Customer Service's typical resource
            event["resource"] = RESOURCES[0]
        else:
            # Fallback: pick a random resource different from current if possible
            current_resource_index = RESOURCES.index(event["resource"]) if event["resource"] in RESOURCES else -1
            possible_resources = [r for i, r in enumerate(RESOURCES) if i != current_resource_index]
            if possible_resources:
                event["resource"] = random.choice(possible_resources)
            # If all else fails, it might remain the same or pick any random one.

    elif anomaly_type == "after_hours_access":
        event["access_request_time"] = datetime.now().replace(hour=random.randint(0, 5), minute=random.randint(0,59), second=random.randint(0,59)).strftime("%Y-%m-%d %H:%M:%S")
        # Resource accessed remains as per base_event_access, anomaly is the time

    elif anomaly_type == "old_os_access":
        event["operatingSystem"] = random.choice(["Windows XP", "Windows 7"])
        event["device_vendor"] = "Unknown Vendor"
        # Resource accessed remains as per base_event_access, anomaly is the OS/vendor

    return event


def generate_batch(count: int, anomaly_ratio: float, ml: bool = True) -> list:
    """Generate a batch of access request events."""
    events = []
    anomaly_count = int(count * anomaly_ratio)
    normal_count = count - anomaly_count
    
    # Generate normal events
    for _ in range(normal_count):
        user = random.choice(USERS)
        if ml:
            event = base_event_ml(user)
        else:
            event = base_event_access(user)
        events.append(event)
    
    # Generate anomalous events
    for _ in range(anomaly_count):
        user = random.choice(USERS)
        if ml:
            event = base_event_ml(user)
            event = mutate_to_anomaly_ml(event)
        else:
            event = base_event_access(user)
            event = mutate_to_anomaly(event)
        events.append(event)
    
    # Shuffle the events to mix normal and anomalous
    random.shuffle(events)
    return events

def save_to_file(events: list, filename: str) -> None:
    """Save events to a JSON file."""
    with open(filename, 'w') as f:
        json.dump(events, f, indent=2)
    print(f"Saved {len(events)} events to {filename}")

# ---------------------------------------------------------------------------#
# 3.  Main loop
# ---------------------------------------------------------------------------#
def main(rps: float, anomaly_ratio: float, ml: bool = True, count: int = None, output: str = None) -> None:
    # If count is specified, generate batch and save to file
    if count is not None:
        events = generate_batch(count, anomaly_ratio, ml)
        if output:
            save_to_file(events, output)
        else:
            # Print to console if no output file specified
            print(json.dumps(events, indent=2))
        return
    
    # Original real-time generation code
    period = 1.0 / rps
    while True:
        user = random.choice(USERS)
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
                resp = requests.post(ACCESS_REQUEST_URL,
                                     json=record, timeout=1.5)
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
    ap.add_argument("--count", type=int,
                    help="generate a specific number of events (batch mode)")
    ap.add_argument("--output", type=str,
                    help="output file for batch generation (e.g., training_requests.json)")
    args = ap.parse_args()
    main(rps=args.rps, anomaly_ratio=args.ratio, ml=args.ml, count=args.count, output=args.output)
