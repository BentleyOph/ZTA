from datetime import datetime
import os

import yaml
from .trust_signal_collection import get_latest_access_request, get_latest_auth_data, get_user_identity_data_by_id

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
    weight_totp_enabled = 0.4
    weight_user_role = 0.2

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
    weight_sign_in_success_ratio = 0.6 # Renamed weight
    weight_auth_type = 0.4

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
        experience_score = 0.6  # Higher experience score
    elif tenure_months >= threshold_1:
        experience_score = 0.8  # Moderate experience score
    else:
        experience_score = 0.4  # Lower experience score

    details = {
        "tenure_months": tenure_months
    }

    return {"overall_score": experience_score, "details": details}





# Get the parent directory path
parent_directory = os.path.abspath(os.path.join(os.getcwd(), os.pardir))

# File path to policyConfiguration.yml
file_path = 'policyConfiguration.yml'

# Load policyConfiguration.yml file
with open(file_path, 'r') as file:
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
    if 'Linux' in device_os:
        device_os_score = 0.5
    else:
        device_os_score = 0.8

    device_type = access_request_data['device_type']
    if device_type == 'Mobile':
        device_type_score = 0.5
    else:
        device_type_score = 0.8

    # Assign weights to attributes
    weight_location = 0.3
    weight_access_time = 0.2
    weight_device_os = 0.25
    weight_device_type = 0.25

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

    # Apply different weights to each segment
    weight_user_identity = 0.3
    weight_access_request = 0.2
    weight_authentication_data = 0.25
    weight_experience = 0.25

    # Calculate overall trust score based on weighted segments
    overall_trust_score = (user_identity_score * weight_user_identity) + \
                          (access_request_score * weight_access_request) + \
                          (authentication_data_score * weight_authentication_data) + \
                          (experience_score * weight_experience)

    # Compile the detailed results
    detailed_result = {
        "overall_score": overall_trust_score,
        "weights": {
            "user_identity": weight_user_identity,
            "access_request": weight_access_request,
            "authentication_data": weight_authentication_data,
            "experience": weight_experience
        },
        "segments": {
            "user_identity": user_identity_result,
            "access_request": access_request_result,
            "authentication_data": authentication_data_result,
            "experience": experience_result
        }
    }

    return detailed_result