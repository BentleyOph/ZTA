import sys
import os
import pandas as pd
from datetime import datetime

PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.insert(0, PARENT_DIR)

# Import the specific function AFTER adjusting sys.path
try:
    from ZeroTrustWebUI.TrustAlgorithm import calculate_overall_trust_score, prepare_features_for_prediction, get_anomaly_score
    from ZeroTrustWebUI.trust_signal_collection import get_latest_access_request 
    print("Successfully imported modules from ZeroTrustWebUI.")
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure the script is run from the correct directory or paths are set correctly.")
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred during import: {e}")
    sys.exit(1)

# --- Test Scenarios ---

# Scenario 1: Use the latest request for a known user from the JSON file
print("\n--- Scenario 1: Latest Request for Existing User ---")
# Use a user_id present in your access_requests.json and other data files
test_user_id_1 = 'b51b2e35-ee9d-4e6a-9118-8c288582219d'
print(f"Testing with User ID: {test_user_id_1}")

try:
    # Option A: Directly test the overall score calculation which includes anomaly
    print("Calculating overall trust score (which includes anomaly score)...")
    overall_score = calculate_overall_trust_score(test_user_id_1)['overall_score']
    print(f"\n==> Overall Trust Score for {test_user_id_1}: {overall_score:.4f}")

    # Option B: Test anomaly score calculation more directly (requires getting the latest request data first)
    # print("\nTesting anomaly score calculation directly...")
    # latest_request_dict = get_latest_access_request(test_user_id_1, os.path.join(PARENT_DIR, 'access_requests.json'))
    # if latest_request_dict:
    #     features_df = prepare_features_for_prediction(latest_request_dict)
    #     anomaly_score = get_anomaly_score(features_df)
    #     print(f"==> Direct Anomaly Score for latest request of {test_user_id_1}: {anomaly_score:.4f}")
    # else:
    #     print(f"Could not find access requests for user {test_user_id_1}")

except Exception as e:
    print(f"An error occurred during Scenario 1 testing: {e}")
    import traceback
    traceback.print_exc()


# Scenario 2: Simulate a potentially anomalous request
print("\n--- Scenario 2: Simulated Anomalous Request ---")
simulated_request = {
    # Use the same user ID or a different one
    'user_id': 'b51b2e35-ee9d-4e6a-9118-8c288582219d',
    # Simulate unusual time (e.g., 3 AM)
    'access_request_time': datetime.now().replace(hour=3, minute=15, second=0).strftime('%Y-%m-%d %H:%M:%S'),
    # Simulate unusual location (e.g., a country not typically seen)
    'location': 'Pyongyang/KP', # Example: North Korea
    'public_ip_address': '175.45.176.1', # Example IP from KP range
    'device_type': 'Mobile', # Maybe unusual for this user?
    'device_mac': '00:11:22:33:44:FF', # Made up MAC
    'device_vendor': 'Unknown Vendor',
    'device_OS': 'Android', # Maybe unusual?
    'resource_requested': 'Admin Console', # Potentially sensitive resource
    'intent': 'Access Request', # Keep consistent if needed by other parts
    # 'ID' is usually assigned when saving, not needed for prediction logic itself
}
print(f"Simulating request: {simulated_request}")

try:
    # We need to directly use the prediction preparation and scoring functions here
    print("Preparing features for simulated request...")
    simulated_features_df = prepare_features_for_prediction(simulated_request)

    print("\nGetting anomaly score for simulated request...")
    simulated_anomaly_score = get_anomaly_score(simulated_features_df)

    print(f"\n==> Anomaly Score for Simulated Request: {simulated_anomaly_score:.4f}")
    # Interpretation: A higher score (closer to 1) indicates higher anomaly likelihood.

except Exception as e:
    print(f"An error occurred during Scenario 2 testing: {e}")
    import traceback
    traceback.print_exc()

print("\n--- Test Script Finished ---")