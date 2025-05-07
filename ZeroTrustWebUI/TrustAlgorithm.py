from datetime import datetime
import os
import joblib
from datetime import datetime,timedelta
import pandas as pd
import numpy as np
import yaml
from .trust_signal_collection import get_latest_access_request, get_latest_auth_data, get_user_identity_data_by_id

PARENT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
ACCESS_REQUESTS_FILE = os.path.join(PARENT_DIR, 'access_requests.json')
USER_DATA_FILE = os.path.join(PARENT_DIR, 'user_data.json')
AUTH_DATA_FILE = os.path.join(PARENT_DIR, 'auth_data.json')
POLICY_CONFIG_FILE = os.path.join(PARENT_DIR, 'policyConfiguration.yml')
MODEL_PATH = os.path.join(PARENT_DIR, 'Anomaly_model', 'isolation_forest_model.joblib')


#Load the Isolation Forest model
anomaly_pipeline = None
try:
    if os.path.exists(MODEL_PATH):
        anomaly_pipeline = joblib.load(MODEL_PATH)
        print("Anomaly detection pipeline loaded successfully.")
    else:
        print(f"Warning: Anomaly detection pipeline not found at {MODEL_PATH}")
except Exception as e:
    print(f"Error loading anomaly detection pipeline: {e}")
    anomaly_pipeline = None # Ensure it's None if loading fails


_access_requests_df_cache = None
_access_requests_mtime = 0

def load_historical_access_requests():
    """Loads historical access requests, using a simple cache based on file modification time."""
    global _access_requests_df_cache, _access_requests_mtime
    try:
        current_mtime = os.path.getmtime(ACCESS_REQUESTS_FILE)
        if _access_requests_df_cache is None or current_mtime > _access_requests_mtime:
            print("(Re)Loading historical access requests for anomaly features...")
            df = pd.read_json(ACCESS_REQUESTS_FILE, orient='records') 
            df['access_request_time'] = pd.to_datetime(df['access_request_time'])
            _access_requests_df_cache = df.sort_values(by='access_request_time') # Sort once
            _access_requests_mtime = current_mtime
            print("Historical data loaded.")
        return _access_requests_df_cache.copy() # Return a copy to prevent modification
    except FileNotFoundError:
        print(f"Error: Historical access requests file not found at {ACCESS_REQUESTS_FILE}")
        return pd.DataFrame() # Return empty DataFrame
    except Exception as e:
        print(f"Error loading historical access requests: {e}")
        return pd.DataFrame()

# --- Feature Preparation for Prediction ---
def prepare_features_for_prediction(current_request_dict):
    """Prepares a feature DataFrame for a single incoming request."""
    print("Preparing features for current request...")
    # Convert single request dict to a DataFrame row
    df = pd.DataFrame([current_request_dict])
    df['access_request_time'] = pd.to_datetime(df['access_request_time'])

    # Handle potential missing values (MUST match training)
    df['location'] = df['location'].fillna('Unknown/Unknown')
    df['device_OS'] = df['device_OS'].fillna('Unknown')
    df['device_type'] = df['device_type'].fillna('Unknown')
    df['resource_requested'] = df['resource_requested'].fillna('Unknown')

    # --- Replicate Feature Engineering ---
    # 1. Temporal Features
    df['hour'] = df['access_request_time'].dt.hour
    df['day_of_week'] = df['access_request_time'].dt.dayofweek
    df['hour_sin'] = np.sin(2 * np.pi * df['hour'] / 24)
    df['hour_cos'] = np.cos(2 * np.pi * df['hour'] / 24)
    df['day_sin'] = np.sin(2 * np.pi * df['day_of_week'] / 7)
    df['day_cos'] = np.cos(2 * np.pi * df['day_of_week'] / 7)

    # --- Load historical data for lookups ---
    historical_df = load_historical_access_requests()
    if historical_df.empty:
         print("Warning: Cannot calculate historical features due to missing data.")
         df['time_since_last_req_sec'] = 0
         df['requests_last_1h'] = 0
         df['requests_last_24h'] = 0
    else:
        user_id = df['user_id'].iloc[0]
        current_time = df['access_request_time'].iloc[0]

        # Filter historical data for the specific user AND time *before* current request
        user_history = historical_df[(historical_df['user_id'] == user_id) &
                                     (historical_df['access_request_time'] < current_time)].copy() # Explicit copy

        # 2. Time Since Last Request
        if not user_history.empty:
            last_req_time = user_history['access_request_time'].iloc[-1] # Already sorted
            time_diff = current_time - last_req_time
            df['time_since_last_req_sec'] = time_diff.total_seconds()
        else:
            df['time_since_last_req_sec'] = 0 # First request for user

        # 3. Frequency Features (use user_history filtered further by time window)
        one_hour_ago = current_time - timedelta(hours=1)
        twenty_four_hours_ago = current_time - timedelta(hours=24)

        # Count requests in the last hour (excluding current)
        reqs_1h = user_history[user_history['access_request_time'] >= one_hour_ago].shape[0]
        df['requests_last_1h'] = reqs_1h

        # Count requests in the last 24 hours (excluding current)
        reqs_24h = user_history[user_history['access_request_time'] >= twenty_four_hours_ago].shape[0]
        df['requests_last_24h'] = reqs_24h

    # 4. Contextual Features
    df['country'] = df['location'].apply(lambda x: x.split('/')[-1] if isinstance(x, str) and '/' in x else 'Unknown')

    # --- Select final features in the correct order (as used in training preprocessor) ---
    # Define the order explicitly based on how the preprocessor was trained
    # It's safer to load this from the saved feature names if possible, but defining here for clarity
    numerical_features = ['hour_sin', 'hour_cos', 'day_sin', 'day_cos', 'time_since_last_req_sec', 'requests_last_1h', 'requests_last_24h']
    categorical_features = ['resource_requested', 'country', 'device_OS', 'device_type']
    feature_columns = numerical_features + categorical_features

    # Ensure all expected columns exist, fill missing numerical with 0, categorical with 'Unknown'
    for col in feature_columns:
        if col not in df.columns:
            print(f"Warning: Feature '{col}' missing in input, adding default value.")
            # Determine if numeric or categorical based on lists
            if col in numerical_features:
                df[col] = 0
            else:
                df[col] = 'Unknown'


    df_final = df[feature_columns] # Select and order columns
    print("Feature preparation for prediction complete.")
    print("Prepared features:\n", df_final.head())
    return df_final



def get_anomaly_score(current_features_df):
    """Calculates the normalized anomaly score using the loaded pipeline."""
    if anomaly_pipeline is None:
        print("Anomaly pipeline not loaded. Returning neutral score (0.5).")
        return 0.5 # Neutral score if model isn't available

    try:
        # Use the pipeline directly - it handles preprocessing
        # decision_function returns raw scores: lower=normal, higher=anomaly
        anomaly_score_raw = anomaly_pipeline.decision_function(current_features_df)

        raw_score = anomaly_score_raw[0] # Get score for the single row
        print(f"Raw Anomaly Score: {raw_score}")

        # --- Normalize the score (0=normal, 1=anomaly) ---
        # !!! IMPORTANT: These min/max values are ESTIMATES based on typical iForest scores.
        # !!! You MUST observe the range of scores from your *training* data's predictions
        # !!! (`results_df['anomaly_score'].describe()` from training script) and adjust these bounds.
        # !!! Or implement a more robust scaling method (e.g., using percentiles).
        min_expected_score = -0.2  # Typical score for clearly normal points (adjust based on training!)
        max_expected_score = 0.15  # Typical score for clearly anomalous points (adjust based on training!)

        # Simple linear scaling
        if max_expected_score <= min_expected_score: # Avoid division by zero
            normalized_score = 0.5 # Fallback if bounds are invalid
        else:
            normalized_score = (raw_score - min_expected_score) / (max_expected_score - min_expected_score)

        # Clamp the score between 0 and 1
        normalized_score = 1 - np.clip(normalized_score, 0, 1) 

        print(f"Normalized Anomaly Score (0=normal, 1=anomaly): {normalized_score}")
        prediction = anomaly_pipeline.predict(current_features_df)
        print(f"Anomaly Prediction: {prediction[0]}")
        return normalized_score

    except Exception as e:
        print(f"Error during anomaly prediction: {e}")
        return 0.5 # Return neutral score on error



def get_anomaly_prediction(current_features_df):
    """Calculates the anomaly prediction using the loaded pipeline."""
    if anomaly_pipeline is None:
        print("Anomaly pipeline not loaded. Returning neutral prediction (0).")
        return 0 # Neutral prediction if model isn't available

    try:
        # Use the pipeline directly - it handles preprocessing
        prediction = anomaly_pipeline.predict(current_features_df)
        print(f"Anomaly Prediction: {prediction[0]}")
        return prediction[0]

    except Exception as e:
        print(f"Error during anomaly prediction: {e}")
        return 0 # Return neutral prediction on error






# Function to calculate User Identity Score
def calculate_user_identity_score(identity_data):
    email_verified_score = 0.0
    totp_enabled_score = 0.0
    user_role_score = 0.0

    # Calculate scores based on email_verified, totp_enabled, and user_role
    if identity_data['email_verified']:
        email_verified_score = 1.0  # Higher score for verified email
    if identity_data['totp_enabled']:
        totp_enabled_score = 1.0  # Higher score for TOTP enabled

    if identity_data['user_role'] == 'Policy Administrator':
        user_role_score = 0.9
    elif identity_data['user_role'] == 'Approver':
        user_role_score = 0.7
    else:
        user_role_score = 0.5


    

    # Assign weights to attributes
    weight_email_verified = 0.4
    weight_totp_enabled = 0.2
    weight_user_role = 0.4

    # Calculate weighted score for user identity
    user_identity_score = (email_verified_score * weight_email_verified) + \
                         (totp_enabled_score * weight_totp_enabled) + \
                         (user_role_score * weight_user_role)

    details = {
        "email_verified": {"score": email_verified_score, "weight": weight_email_verified},
        "totp_enabled": {"score": totp_enabled_score, "weight": weight_totp_enabled},
        "user_role": {"score": user_role_score, "weight": weight_user_role, "role": identity_data['user_role']}
    }

    return {"overall_score": user_identity_score, "details": details}

# Function to calculate Authentication Data Score
def calculate_authentication_data_score(authentication_data):
    sign_in_success_ratio = authentication_data['sign_in_success_ratio'] # Renamed variable
    auth_type_score = 0.0
    sign_in_success_ratio_score = 0.0 # Renamed variable

    # Consider sign_in_success_ratio and auth_type
    # Higher success ratio should lead to a higher score contribution
    if sign_in_success_ratio >= 0.9:
        sign_in_success_ratio_score = 0.9
    elif sign_in_success_ratio >= 0.7:
        sign_in_success_ratio_score = 0.75
    elif sign_in_success_ratio >= 0.5:
        sign_in_success_ratio_score = 0.5
    else: # Lower success ratio means lower score contribution
        sign_in_success_ratio_score = 0.3

    # Evaluate auth_type and assign scores
    if authentication_data['auth_type'] == 'code':
        auth_type_score = 0.7
    else:
        auth_type_score = 0.5

    # Assign weights to attributes
    weight_sign_in_success_ratio = 0.9 # Renamed weight
    weight_auth_type = 0.1

    # Calculate weighted score for authentication data
    authentication_data_score = (sign_in_success_ratio_score * weight_sign_in_success_ratio) + \
                                (auth_type_score * weight_auth_type)

    details = {
        "sign_in_success_ratio": {"score": sign_in_success_ratio_score, "weight": weight_sign_in_success_ratio, "value": sign_in_success_ratio}, # Renamed key
        "auth_type": {"score": auth_type_score, "weight": weight_auth_type, "value": authentication_data['auth_type']}
    }

    return {"overall_score": authentication_data_score, "details": details}

# Function to calculate Experience Score
def calculate_experience_score(created_timestamp):
    # Get the current timestamp in milliseconds (assuming it's in milliseconds)
    current_timestamp = datetime.now().timestamp() * 1000

    # Calculate tenure in milliseconds by finding the difference between current time and user's creation time
    tenure_ms = current_timestamp - created_timestamp

    # Convert tenure from milliseconds to months
    tenure_months = tenure_ms / (1000 * 60 * 60 * 24 * 30)  # Assuming 30 days in a month

    # Define thresholds for experience (in months)
    threshold_1 = 1
    threshold_2 = 0.15 

    # Assign scores based on tenure
    if tenure_months >= threshold_2:
        experience_score = 0.6  
    elif tenure_months >= threshold_1:
        experience_score = 0.8  
    else:
        experience_score = 0.4  

    details = {
        "tenure_months": tenure_months
    }

    return {"overall_score": experience_score, "details": details}





#

# Load policyConfiguration.yml file
with open(POLICY_CONFIG_FILE, 'r') as file:
    policy_configurations = yaml.safe_load(file)

# Extract country lists for each risk category
high_risk_countries = policy_configurations.get('highRiskLocations', [])
medium_risk_countries = policy_configurations.get('mediumRiskLocations', [])
print(medium_risk_countries)
low_risk_countries = policy_configurations.get('lowRiskLocations', [])

# Extract night start and night end times and convert to datetime objects
period_start = policy_configurations.get('periodStartInput', '00:00:00')
period_end = policy_configurations.get('periodEndInput', '06:00:00')

night_start_time = datetime.strptime(period_start, '%H:%M:%S').time()
night_end_time = datetime.strptime(period_end, '%H:%M:%S').time()

# Function to assign trust scores based on access request data for the user_id
def calculate_access_request_score(access_request_data, night_start=night_start_time, night_end=night_end_time,high_risk_locations=high_risk_countries, medium_risk_locations=medium_risk_countries, low_risk_locations=low_risk_countries):
    location_score = 0.0
    access_time_score = 0.0
    device_os_score = 0.0
    device_type_score = 0.0

   # Evaluate location, access request time, device_os, and device_type
    location_risk = access_request_data['location']
    location_category = "Unknown" # Default category
    if high_risk_locations and location_risk in high_risk_locations:
        location_score = 0.15
        location_category = "High Risk"
    elif medium_risk_locations and location_risk in medium_risk_locations:
        location_score = 0.4
        location_category = "Medium Risk"
    elif low_risk_locations and location_risk in low_risk_locations:
        location_score = 0.7
        location_category = "Low Risk"
    else:
        location_score = 0.1  # Assign a default score for locations not specified

    # Assess access request time
    access_time = datetime.strptime(access_request_data['access_request_time'], '%Y-%m-%d %H:%M:%S')

    # Check if the access time falls within the specified night time boundaries
    night_start_time_obj = night_start # Already time object
    night_end_time_obj = night_end     # Already time object
    is_night_access = False

    if night_start_time_obj <= night_end_time_obj: # Normal case (e.g., 00:00 to 06:00)
        if night_start_time_obj <= access_time.time() <= night_end_time_obj:
            access_time_score = 0.6
            is_night_access = True
        else:
            access_time_score = 0.8
    else: # Overnight case (e.g., 22:00 to 06:00)
        if night_start_time_obj <= access_time.time() or access_time.time() <= night_end_time_obj:
             access_time_score = 0.6
             is_night_access = True
        else:
             access_time_score = 0.8


    # Evaluate device_os and device_type
    device_os = access_request_data['device_OS']
    if 'Win32' in device_os:
        device_os_score = 0.8
    else:
        device_os_score = 0.5

    device_type = access_request_data['device_type']
    if device_type == 'Mobile':
        device_type_score = 0.5
    else:
        device_type_score = 0.8

    # Assign weights to attributes
    weight_location = 0.4
    weight_access_time = 0.3
    weight_device_os = 0.2
    weight_device_type = 0.1

    # Calculate weighted score for access request
    access_request_score = (location_score * weight_location) + \
                           (access_time_score * weight_access_time) + \
                           (device_os_score * weight_device_os) + \
                           (device_type_score * weight_device_type)

    details = {
        "location": {"score": location_score, "weight": weight_location, "value": location_risk, "category": location_category},
        "access_time": {"score": access_time_score, "weight": weight_access_time, "value": access_request_data['access_request_time'], "is_night": is_night_access},
        "device_os": {"score": device_os_score, "weight": weight_device_os, "value": device_os},
        "device_type": {"score": device_type_score, "weight": weight_device_type, "value": device_type}
    }

    return {"overall_score": access_request_score, "details": details}

# Function to calculate Overall Trust Score
def calculate_overall_trust_score(user_id):

    # Get user data using provided functions
    identity_data = get_user_identity_data_by_id(user_id,'user_data.json')
    access_request_data = get_latest_access_request(user_id, 'access_requests.json')
    authentication_data = get_latest_auth_data(user_id, 'auth_data.json')

    if not identity_data or not access_request_data or not authentication_data:
        print("Error: Missing required data for trust calculation. Returning low score.")
        return 0.1
    anomaly_score = 0.5 # Default neutral score
    if anomaly_pipeline:
        try:
             # Prepare features for the *current* (latest) access request
             features_df = prepare_features_for_prediction(access_request_data)
             anomaly_score = get_anomaly_score(features_df)
        except Exception as e:
             print(f"Error during feature prep/anomaly scoring: {e}. Using default anomaly score.")
             anomaly_score = 0.5 # Use default on error
    else:
        print("Anomaly pipeline not loaded, using default anomaly score.")



    # Calculate scores for each segment (these now return dictionaries)
    user_identity_result = calculate_user_identity_score(identity_data)
    access_request_result = calculate_access_request_score(access_request_data)
    authentication_data_result = calculate_authentication_data_score(authentication_data)
    experience_result = calculate_experience_score(identity_data['created_timestamp'])

    

    # Extract overall scores for final calculation
    user_identity_score = user_identity_result["overall_score"]
    access_request_score = access_request_result["overall_score"]
    authentication_data_score = authentication_data_result["overall_score"]
    experience_score = experience_result["overall_score"]

    print(f"  Identity Score: {user_identity_score:.3f}")
    print(f"  Context/Access Score: {access_request_score:.3f}")
    print(f"  Auth Score: {authentication_data_score:.3f}")
    print(f"  Experience Score: {experience_score:.3f}")
    print(f"  Anomaly probability score: {anomaly_score:.3f}")


    weight_user_identity = float(policy_configurations.get('userIdentityWeight', 0.3))
    weight_access_request = float(policy_configurations.get('contextScoreWeight', 0.25))
    weight_authentication_data = float(policy_configurations.get('authScoreWeight', 0.2))
    weight_experience = float(policy_configurations.get('expScoreWeight', 0.15)) # Adjusted slightly
    # *** Add anomalyScoreWeight to your policyConfiguration.yml ***
    weight_anomaly = float(policy_configurations.get('anomalyScoreWeight', 0.1))


    # Calculate overall trust score based on weighted segments
    overall_trust_score = (user_identity_score * weight_user_identity) + \
                          (access_request_score * weight_access_request) + \
                          (authentication_data_score * weight_authentication_data) + \
                          (experience_score * weight_experience) + \
                            ((1-anomaly_score) * weight_anomaly)

    # Compile the detailed results
    detailed_result = {
        "overall_score": overall_trust_score,
        "weights": {
            "user_identity": weight_user_identity,
            "access_request": weight_access_request,
            "authentication_data": weight_authentication_data,
            "experience": weight_experience,
            "anomaly": weight_anomaly
        },
        "segments": {
            "user_identity": user_identity_result,
            "access_request": access_request_result,
            "authentication_data": authentication_data_result,
            "experience": experience_result,
            "anomaly_prob": anomaly_score
        }
    }

    return detailed_result