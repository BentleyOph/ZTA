import json
import os
import sys
from flask import Flask,render_template, request, jsonify, session, url_for,redirect, make_response
import logging
import math
from flask import Flask
from flask_oidc import OpenIDConnect
from keycloak import KeycloakAuthenticationError, KeycloakOpenID
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
import yaml
from Networking import Networking
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection
import re, uuid
from .keycloak_config import *
from .PAM import PAM
from .Keycloak_functions import *
from .PAM_Mail_Notification import send_email_to_approver
from .trust_signal_collection import store_keycloak_events,load_events_data,process_events
from .TrustAlgorithm import prepare_features_for_prediction, get_anomaly_score,get_anomaly_prediction
import time 

sys.path.insert(0,'..')

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_SECRETS_FILE = os.path.join(APP_DIR, 'client_secrets.json')
ANOMALY_DISPLAY_THRESHOLD = 0.6  

'''
This section below contains the configuration of the flask OIDC and the keycloak OIDC
'''

app.config['OIDC_SESSION_TYPE'] = 'null'

app.config.update({
    'SECRET_KEY': 'bzf9bctfGor9tB2rOfLdQnK3VNDxt6rx',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': CLIENT_SECRETS_FILE,
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'myrealm',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_TOKEN_TYPE_HINT': 'access_token',
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

keycloak_connection = KeycloakOpenIDConnection(
                        server_url="http://localhost:8080/",
                        username='admin',
                        password='admin',
                        realm_name="myrealm",
                        user_realm_name="master",
                        client_id="admin-cli",
                        client_secret_key=KEYCLOAK_ADMIN_CLIENT_SECRET,
                        verify=False)

keycloak_admin = KeycloakAdmin(connection=keycloak_connection)

oidc = OpenIDConnect(app)

# Configure client for end user authentication
keycloak_openid = KeycloakOpenID(server_url="http://localhost:8080/",
                                 client_id=KEYCLOAK_CLIENT_ID,
                                 realm_name=KEYCLOAK_REALM,
                                 client_secret_key=KEYCLOAK_CLIENT_SECRET)

# Configuration for SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///privileged_access.db' 
db = SQLAlchemy(app)

# Define the database model for access requests
class AccessRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    resource_name = db.Column(db.String(100), nullable=False)
    reason_for_access = db.Column(db.String(250), nullable=False)
    access_duration = db.Column(db.Integer, nullable=False)
    requestor_id = db.Column(db.String(100), nullable=False)
    requestor_username = db.Column(db.String(100), nullable=False)
    time_of_request = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    requestStatus = db.Column(db.String(20), default="pending")
    secret_key = db.Column(db.String(128), nullable=True)

# Create a new database model for approvers
class Approver(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    approverID = db.Column(db.String(100), nullable=False)
    approverEmail = db.Column(db.String(100), nullable=False)
    request_id = db.Column(db.Integer, db.ForeignKey('access_request.id'), nullable=False)
    approver_secret_share = db.Column(db.String(750))
    approver_action = db.Column(db.String(20))


THRESHOLD = None 

'''

The section below contains the system views. They contain the various routes in the web UI and the functionalities
that can be performed at each view

'''
#Main route
@app.route('/')
def index():
    if oidc.user_loggedin and token_is_valid(oidc,keycloak_openid):
        return redirect(url_for('home'))
    else:
        return render_template('index.html')
    
#create a route to revoke an access token and redirect to index.html page for the user to authenticate
@app.route('/revokeToken')
@oidc.require_login
def revokeToken():
    refresh_token = oidc.get_refresh_token()
    if revoke_token(KEYCLOAK_CLIENT_ID,KEYCLOAK_CLIENT_SECRET,refresh_token, REVOCATION_URL):
        return render_template('index.html')
    else:
        return "<h1>Failed to revoke the access token!<h1>"
    
#Login Route 
@app.route('/login')
@oidc.require_login
def login():
    token = oidc.get_access_token()
    response = make_response(redirect(url_for('home')))
    if token_is_valid(oidc,keycloak_openid):
        response.set_cookie('access_token', token['access_token'])
        session['access_token'] = token['access_token']  
        return response
    else:
        return render_template('index.html')
    

# The home route where all the available services are located
@app.route('/home')
def home():
    try:
        if oidc.user_loggedin:

            if token_is_valid(oidc,keycloak_openid):
                if 'oidc_auth_profile' in session:
                    auth_profile = session['oidc_auth_profile']
                    username = auth_profile.get('name')
                    email = auth_profile.get('email')
                    user_id = auth_profile.get('sub')
                    #get the user role
                    user_roles = extract_user_role(oidc,keycloak_openid)
                    user_role = user_roles[0]

                    #storing keycloak events
                    store_keycloak_events(keycloak_admin)

                    parent_directory = os.path.join(APP_DIR, os.pardir)

                    # Define the path to events.json in the parent directory
                    events_file_path = os.path.join(parent_directory, 'events.json')

                    events_data = load_events_data(events_file_path)
                    # Process event data to yield the auth_data
                    if events_data:
                        process_events(events_data)
                    else:
                        print("Failed to load events data.")

                    all_users = keycloak_admin.get_users()
                    print(all_users)

                    file_path = os.path.join(parent_directory, 'user_data.json')

                    # Extracting user data
                    extracted_data = []
                    for user in all_users:
                        user_info = {
                            'user_id': user['id'],
                            'username': user['username'],
                            'email': user['email'],
                            'created_timestamp': user['createdTimestamp'],
                            'email_verified': user['emailVerified'],
                            'totp_enabled': user['totp'],
                            'user_role': user_role if user['id'] == user_id else None  # We'll preserve roles from existing data
                        }
                        extracted_data.append(user_info)

                    # Load existing data from the file if it exists
                    existing_data = []
                    if os.path.exists(file_path):
                        with open(file_path, 'r') as json_file:
                            existing_data = json.load(json_file)

                    # Create a mapping of user_id to user_role from existing data
                    existing_roles = {user['user_id']: user.get('user_role') for user in existing_data}

                    # Update extracted data with existing roles where applicable
                    for user in extracted_data:
                        if user['user_id'] in existing_roles and existing_roles[user['user_id']] is not None:
                            user['user_role'] = existing_roles[user['user_id']]
                        elif user['user_id'] == user_id:
                            # Ensure current user has their role set
                            user['user_role'] = user_role

                    # Store the updated data in the JSON file
                    with open(file_path, 'w') as json_file:
                        json.dump(extracted_data, json_file, indent=4)

                    return render_template('home.html', username=username, email=email, user_id=user_id, user_role=user_role,current_timestamp_for_template=datetime.now().timestamp())
                else:
                    return "<h1>NOT AUTHORIZED!</h1>"
            else:
                return "<h1>UNAUTHORIZED [INVALID ACCESS TOKEN]!!!</h1>"
        else:
            return redirect(url_for('login'))
    except KeycloakAuthenticationError as e:
        print(f"KeycloakAuthenticationError: {e}")
        return redirect(url_for('index'))
    



#route to receive an access request and forward it to the AP
# Initialize Networking Node Globally
node4 = Networking("127.0.0.1", 8004, 4)
node4.start()
node4.connect_with_node('127.0.0.1', 8001) # connect with the access proxy
node4.connect_with_node('127.0.0.1', 8003) # connect with the policy engine

# Note: A proper shutdown mechanism for node4 might be needed for production environments.




# Function to get the latest access decision data from the JSON file
def get_latest_access_decision(request_id):
    latest_decision = None
    
    parent_directory = os.path.join(APP_DIR, os.pardir)
    
    file_path = os.path.join(parent_directory, 'access_decision.json')

    if os.path.exists(file_path):
        try:
            with open(file_path, 'r') as file:
                access_decisions = json.load(file)
                matching_decisions = [d for d in access_decisions if d.get('request_ID') == request_id]
                if matching_decisions:
                    latest_decision = max(matching_decisions, key=lambda x: x.get('timestamp', 0))
        except json.JSONDecodeError:
            print(f"Error decoding JSON from {file_path}")
            return None
        except Exception as e:
            print(f"Error reading or processing {file_path}: {e}")
            return None
            
    return latest_decision

#route to receive an access request and forward it to the AP
@app.route('/receive-access-request', methods = ['POST'])
def receive_and_process_access_request():
    data = request.json
    current_user_id = data.get("userId")

    pam_request_id = session.get('privileged_access_active_for_request_id')
    pam_user_id_in_session = session.get('privileged_access_user_id')
    pam_expires_at = session.get('privileged_access_expires_at')

    if pam_request_id and pam_user_id_in_session == current_user_id and \
       pam_expires_at and datetime.now().timestamp() < pam_expires_at:
        
        # Verify that the PAM request ID still corresponds to an 'approved' request
        # This is a safety check in case the request status was somehow changed after PAM activation
        active_pam_request = AccessRequest.query.filter_by(id=pam_request_id, requestor_id=current_user_id, requestStatus='approved').first()
        if active_pam_request:
            print(f"PAM session active for user {current_user_id} (Request ID: {pam_request_id}). Granting direct access to '{data.get('resource')}'.")
            # Log this PAM-overridden access if necessary
            # For now, just return success with a flag
            return jsonify({'verdict': 1, 'pam_override': True})
        else:
            print(f"Warning: PAM session data found for user {current_user_id}, but original PAM request (ID: {pam_request_id}) is no longer valid or approved. Clearing stale PAM session.")
            session.pop('privileged_access_active_for_request_id', None)
            session.pop('privileged_access_user_id', None)
            session.pop('privileged_access_expires_at', None)    




    access_requests_file_path = os.path.join(os.path.join(APP_DIR, os.pardir), 'access_requests.json') 
    existing_data = []
    new_id = 1

    try:
        if os.path.exists(access_requests_file_path):
            with open(access_requests_file_path, 'r') as file:
                existing_data = json.load(file)
                if existing_data:
                    last_entry = existing_data[-1]
                    if isinstance(last_entry, dict) and 'ID' in last_entry:
                         new_id = last_entry['ID'] + 1
                    else:
                         new_id = len(existing_data) + 1
                         print(f"Warning: Last entry in access_requests.json is not a dict with 'ID'. Assigning ID: {new_id}")
    except(json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error occurred while loading JSON data: {e}")
    except IndexError:
        print("access_requests.json is empty. Starting with ID 1.")
        new_id = 1

    access_request = {
        'ID': new_id,
        'user_id': data.pop('userId'),
        'intent': data['intent'],
        'resource_requested': data['resource'],
        'access_request_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'public_ip_address': data['public_ip'],
        'location': data['location'],
        'device_type': data['deviceType'],
        'browser': data['userAgent'],
        'device_mac': data['device_mac'],
        'device_vendor': data['device_vendor'],
        'device_OS': data['operatingSystem']
    }

    existing_data.append(access_request)

    try:
        with open(access_requests_file_path, 'w') as file:
            json.dump(existing_data, file, indent=4)

    except IOError as e:
        print(f"Error occured while writing to the json data {e}")
        return jsonify({'error': 'Failed to save access request log'}), 500
    
    node4.send_message_to_node('1', access_request)

    access_decision = None
    policy_engine_verdict = "pending"
    max_wait_time = 120
    poll_interval = 0.5
    start_time = time.time()

    print(f"Waiting for access decision for request ID: {new_id}...")

    while time.time() - start_time < max_wait_time:
        access_decision = get_latest_access_decision(new_id)
        # Check if the decision dictionary exists and the 'access_decision' key is present (value can be 0 or 1)
        if access_decision and access_decision.get('access_decision') is not None:
            policy_engine_verdict = access_decision.get('access_decision')
            print(f"Received decision: {policy_engine_verdict}")
            break
        else:
            print(f"Decision not found yet, waiting {poll_interval}s...")
            time.sleep(poll_interval)
    
    # Check the final state after the loop
    if not access_decision or access_decision.get('access_decision') is None:
         print(f"Timeout or error waiting for access decision for request ID: {new_id}.")
         policy_engine_verdict = "timeout" # Keep timeout verdict if no decision was found

    print(f"Final Policy Engine Verdict: {policy_engine_verdict}")

    response_data = {'verdict': policy_engine_verdict}
    return jsonify(response_data)

@app.route('/resource-selection')
@oidc.require_login
def resource_selection():
    if 'oidc_auth_profile' in session:
        auth_profile = session['oidc_auth_profile']
        user_id = auth_profile.get('sub')

        #get location, public ip, device mac and device vendor

        location_info = get_location(ip_address=get_public_ip())
        ip = location_info.get('ip')
        city = location_info.get('city')
        country = location_info.get('country')
        location = f"{city}/{country}"

        # Get the device mac and device vendor
        device_mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        device_vendor = get_mac_details(device_mac)

    return render_template('resourceSelection.html',user_id=user_id,location=location,public_ip=ip,device_mac=device_mac,device_vendor=device_vendor)

@app.route('/resource-1')
def display_transactions():
    # Load transactions from the JSON file
    filepath = os.path.join(APP_DIR, 'mobile_money_transactions.json')
    with open(filepath, 'r') as file:
        transactions = json.load(file)
    
    return render_template('transaction_simulation.html', transactions=transactions)

@app.route('/resource-2')
def display_loans():
    # Load loans from JSON file
    file_path = os.path.join(APP_DIR, 'disbursed_loans.json')
    with open(file_path, 'r') as file:
        loans = json.load(file)
    
    return render_template('disbursed_loans.html', loans=loans)

@app.route('/resource-3')
def display_customer_accounts():
    # Load customer accounts from JSON file
    file_path = os.path.join(APP_DIR, 'customer_accounts.json')
    with open(file_path, 'r') as file:
        accounts = json.load(file)
    
    return render_template('customer_accounts.html', accounts=accounts)






# Function to create or update policyConfiguration.yml file
def update_policy_configurations(data):
    # Get the parent directory path
    parent_directory = os.path.join(APP_DIR, os.pardir)

    file_path = os.path.join(parent_directory, 'policyConfiguration.yml')
    
    try:
        with open(file_path, 'r') as file:
            existing_data = yaml.safe_load(file)
    except FileNotFoundError:
        existing_data = {}

    existing_data.update(data)

    with open(file_path, 'w') as file:
        yaml.dump(existing_data, file)

@app.route('/receivePolicyConfigurations', methods=['POST'])
def receive_policy_configurations():
    if request.method == 'POST':
        data = request.json  # Get JSON data from the POST request
        print(data)

        #update coinfigurations in the Policy YML file
        update_policy_configurations(data)
        print("Received Policy Configurations:")
        for key, value in data.items():
            print(f"{key}: {value}")
        return 'Received Policy Configurations successfully!', 200
    else:
        return 'Invalid request method', 405



@app.route('/logging')
@oidc.require_login
def access_requests():
    parent_dir = os.path.join(APP_DIR, os.pardir)
    access_requests_file = os.path.join(parent_dir, 'access_requests.json')
    access_decisions_file = os.path.join(parent_dir, 'access_decision.json')

    access_requests_data = []
    if os.path.exists(access_requests_file):
        try:
            with open(access_requests_file, 'r') as f:
    
                access_requests_data = json.load(f)
            if not isinstance(access_requests_data, list): # Ensure it's a list
                    access_requests_data = []
        except json.JSONDecodeError:
            print(f"Error decoding {access_requests_file}")
            access_requests_data = []
    
    access_decisions_data = []
    if os.path.exists(access_decisions_file):
        try:
            with open(access_decisions_file, 'r') as f:
                access_decisions_data = json.load(f)
            if not isinstance(access_decisions_data, list): # Ensure it's a list
                    access_decisions_data = []
        except json.JSONDecodeError:
            print(f"Error decoding {access_decisions_file}")
            access_decisions_data = []

    # Create a dictionary of decisions for efficient lookup
    decisions_map = {}
    if access_decisions_data:
        sorted_decisions = sorted(access_decisions_data, key=lambda x: x.get('timestamp', 0), reverse=True)
        for decision in sorted_decisions:
            req_id = decision.get('request_ID')
            if isinstance(req_id, (int, str)) and req_id not in decisions_map: # Ensure req_id is valid and take latest
                decisions_map[req_id] = decision
    
    combined_logs = []
    for req in access_requests_data:
        if not isinstance(req, dict): continue # Skip non-dict items
        
        log_entry = req.copy() # Start with all fields from access_requests.json
        decision = decisions_map.get(req.get('ID'))

        if decision:
            log_entry['user_trust_score'] = decision.get('user_trust_score', 'N/A')
            
            # Safely access nested anomaly_prob
            trust_details = decision.get('trust_score_details', {})
            log_entry['anomaly_prob'] = trust_details.get('anomaly_prob') # Check root first
            if log_entry['anomaly_prob'] is None: # If not at root, check segments (older structure)
                 segments = trust_details.get('segments', {})
                 log_entry['anomaly_prob'] = segments.get('anomaly_prob', 'N/A')
            if not isinstance(log_entry['anomaly_prob'], (float, int)): # If still N/A or other, format
                 log_entry['anomaly_prob'] = 'N/A'


            log_entry['access_decision_val'] = decision.get('access_decision', 'Pending') # Store raw value
            log_entry['decision_timestamp'] = decision.get('timestamp')
        else:
            log_entry['user_trust_score'] = 'N/A'
            log_entry['anomaly_prob'] = 'N/A'
            log_entry['access_decision_val'] = 'Pending'
            log_entry['decision_timestamp'] = None
        
        combined_logs.append(log_entry)

    # User info for the sidebar
    auth_profile = session.get('oidc_auth_profile', {})
    user_role = session.get('user_role', "User")

    return render_template('logging_and_monitoring.html', 
                           access_logs=combined_logs,
                           username=auth_profile.get('name'),
                           email=auth_profile.get('email'),
                           user_id=auth_profile.get('sub'),
                           user_role=user_role)



@app.template_filter('timestamp_to_datetime')
def timestamp_to_datetime_filter(s):
    if s is None or s == 'N/A':
        return 'N/A'
    try:
        # Assuming s is a UNIX timestamp (seconds since epoch)
        return datetime.fromtimestamp(float(s)).strftime('%Y-%m-%d %H:%M:%S')
    except (ValueError, TypeError):
        return 'Invalid Timestamp'



@app.route('/configurePolicies')
def configure_policies():
    return render_template('policyConfiguration.html')

@app.route('/privilegedAccess', methods=['GET', 'POST'])
@oidc.require_login
def privilegedAccess():
    current_user_id = session['oidc_auth_profile'].get('sub')
    username = session['oidc_auth_profile'].get('name') # For sidebar
    email = session['oidc_auth_profile'].get('email')   # For sidebar
    user_role = session.get('user_role', "User")      # For sidebar
    
    # Check if user has any pending PAM request to inform them
    existing_pending_request_for_user = AccessRequest.query.filter_by(
        requestor_id=current_user_id,
        requestStatus='pending'
    ).order_by(AccessRequest.id.desc()).first()
    
    client_id = keycloak_admin.get_client_id(KEYCLOAK_CLIENT_ID)
    # Define roles that can be approvers
    approver_role_names = ["Security Analyst", "Branch Manager"] 
    email_addresses = get_multiple_client_role_members_emails(keycloak_admin, client_id, approver_role_names)

    num_total_approvers = len(email_addresses)
    global THRESHOLD # Ensure THRESHOLD is accessible for new requests

    # Calculate THRESHOLD for new requests based on currently available approvers
    if num_total_approvers == 0:
        THRESHOLD = 0 
    elif num_total_approvers == 1:
        THRESHOLD = 1
    else:
        calculated_threshold = math.floor(num_total_approvers * 0.8)
        THRESHOLD = max(2, calculated_threshold)
    print(f"Calculated THRESHOLD for new requests: {THRESHOLD} (based on {num_total_approvers} total approvers)")

    if request.method == 'POST':
        resource_name = "All resources" # As per current logic
        reason_for_access = request.form['reason_for_access']
        access_duration = int(request.form['access_duration'])
        requestor_username = session['oidc_auth_profile'].get('preferred_username')
        time_of_request = datetime.now()
        selected_approvers = request.form.getlist('approvers')
        num_selected_shares = len(selected_approvers)

        error_message = None
        if num_total_approvers == 0:
            error_message="No approvers available for PAM request. Cannot create."
        elif THRESHOLD == 0 and num_total_approvers > 0: # Should ideally not be hit if above is correct
            error_message="System error: Invalid approval threshold calculated."
        elif num_selected_shares < THRESHOLD:
            error_message=f"Please select at least {THRESHOLD} approver(s). You selected {num_selected_shares}."
        elif not (1 <= access_duration <= 100):
            error_message="Invalid access duration. Please enter a value between 1 and 100 minutes."

        if error_message:
            return render_template('privilegedAccessManagement.html', 
                                   email_addresses=email_addresses, 
                                   existing_pending_request=existing_pending_request_for_user,
                                   error_message=error_message,
                                   username=username, email=email, user_id=current_user_id, user_role=user_role)

        secret_key = PAM.generate_secret_message(45)
        secret_key_identifier = PAM.generate_secret_message(4) 
        # Use the THRESHOLD calculated for new requests for share generation
        secret_shares_list = PAM.generate_secret_shares(THRESHOLD, num_selected_shares, secret_key, secret_key_identifier)

        new_request = AccessRequest(
            resource_name=resource_name,
            reason_for_access=reason_for_access,
            access_duration=access_duration,
            requestor_id=current_user_id,
            requestor_username=requestor_username,
            time_of_request=time_of_request,
            requestStatus='pending',  
            secret_key=secret_key    
        )
        db.session.add(new_request)
        try:
            db.session.commit() # Commit to get new_request.id
        except Exception as e:
            db.session.rollback()
            print(f"Error saving access request: {e}")
            return render_template('privilegedAccessManagement.html', 
                                   email_addresses=email_addresses, 
                                   existing_pending_request=existing_pending_request_for_user,
                                   error_message="Error saving request. Please try again.",
                                   username=username, email=email, user_id=current_user_id, user_role=user_role)

        for index, approver_email_addr in enumerate(selected_approvers):
            approver_user_id = get_user_id_by_email(keycloak_admin, approver_email_addr)
            if not approver_user_id:
                print(f"Warning: Could not find user ID for approver email {approver_email_addr}")
                # Decide how to handle: skip this approver, or fail request? For now, skip.
                continue 
            
            approver_secret_share = secret_shares_list[index] 
            send_email_to_approver(approver_email_addr, current_user_id, requestor_username, reason_for_access, access_duration, approver_secret_share)

            approver = Approver(
                approverID=approver_user_id,
                approverEmail=approver_email_addr,
                request_id=new_request.id,
                approver_secret_share=approver_secret_share  
            )
            db.session.add(approver)
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            # Clean up the created AccessRequest if saving approvers fails
            AccessRequest.query.filter_by(id=new_request.id).delete()
            db.session.commit()
            print(f"Error saving approvers for request {new_request.id}: {e}")
            return render_template('privilegedAccessManagement.html', 
                                   email_addresses=email_addresses, 
                                   existing_pending_request=existing_pending_request_for_user,
                                   error_message="Error saving approver details. Request cancelled.",
                                   username=username, email=email, user_id=current_user_id, user_role=user_role)

        return redirect(url_for('approval_status', request_id=new_request.id))

    return render_template('privilegedAccessManagement.html', 
                           email_addresses=email_addresses, 
                           existing_pending_request=existing_pending_request_for_user,
                           username=username, email=email, user_id=current_user_id, user_role=user_role)


@app.route('/approval_status/<int:request_id>', methods=['GET','POST']) # request_id is now mandatory
@oidc.require_login
def approval_status(request_id):
    global THRESHOLD 
    current_user_id = session['oidc_auth_profile'].get('sub')
    username = session['oidc_auth_profile'].get('name')
    email = session['oidc_auth_profile'].get('email')
    user_role = session.get('user_role', "User")

    target_request = AccessRequest.query.filter_by(id=request_id, requestor_id=current_user_id).first()

    if not target_request:
        # flash(f"PAM Request ID {request_id} not found or you do not have permission to view it.", "error")
        return redirect(url_for('home')) 

    secret_from_db = target_request.secret_key

    associated_approvers = Approver.query.filter_by(request_id=target_request.id).all()
    approvers_count = len(associated_approvers) # This is 'n' for this specific request
    approved_approvers_records = [appr for appr in associated_approvers if appr.approver_action == 'approved']
    approved_approvers_count = len(approved_approvers_records)

    # THRESHOLD ('k') for *this specific request* should be based on how shares were generated.
    # If THRESHOLD was stored with the request, use that. Otherwise, recalculate based on assigned approvers.
    # For simplicity, let's recalculate. This implies 'k' is dynamic for policy rather than fixed at share creation.
    # A more robust system might store 'k' with the AccessRequest.
    if approvers_count == 0:
        current_request_threshold = 0 # Cannot be approved
    elif approvers_count == 1:
        current_request_threshold = 1
    else:
        calculated_threshold = math.floor(approvers_count * 0.8) # Example policy
        current_request_threshold = max(2, calculated_threshold)
    
    APPROVAL_WINDOW_MINUTES = 60 
    current_time = datetime.now()
    approval_expiration_time = target_request.time_of_request + timedelta(minutes=APPROVAL_WINDOW_MINUTES) 
    approval_expiration_time_iso = approval_expiration_time.isoformat()
    
    is_expired_for_approval = current_time > approval_expiration_time

    if request.method == 'POST':
        data = request.json
        action = data.get('action')

        if action == 'reconstruct_secret':
            if is_expired_for_approval and target_request.requestStatus != 'approved':
                return jsonify({'ERR_EXPIRED': 'This PAM request has expired for approval. Please create a new request.'}), 400
            
            if approved_approvers_count >= current_request_threshold: # Use specific request's threshold
                secret_shares = [approver.approver_secret_share for approver in approved_approvers_records if approver.approver_secret_share] 

                if len(secret_shares) < current_request_threshold:
                     print(f"Error: Not enough valid shares for request {target_request.id} despite {approved_approvers_count} approvals needed {current_request_threshold}.")
                     return jsonify({'ERR_RECONSTRUCT': 'Could not retrieve enough valid shares for reconstruction.'}), 500

                reconstructed_secret_val = PAM.reconstruct_secret_from_base64_shares(secret_shares)
                reconstructed_secret_str = None
                if isinstance(reconstructed_secret_val, bytes):
                    try: reconstructed_secret_str = reconstructed_secret_val.decode('utf-8')
                    except UnicodeDecodeError: reconstructed_secret_str = str(reconstructed_secret_val)
                elif isinstance(reconstructed_secret_val, str): reconstructed_secret_str = reconstructed_secret_val
                else: reconstructed_secret_str = str(reconstructed_secret_val)

                if reconstructed_secret_str == secret_from_db:
                    if target_request.requestStatus != 'approved':
                        target_request.requestStatus = 'approved'
                        db.session.commit()
                    return jsonify({'reconstructed_secret': reconstructed_secret_str, 'message': 'Secret reconstructed successfully.'})
                else:
                    print(f"Error: Reconstructed secret for request {target_request.id} does not match DB.")
                    return jsonify({'ERR_RECONSTRUCT': 'Secret reconstruction failed or mismatch.'}), 500
            else: 
                 return jsonify({'ERR_THRESH': f'Minimum Threshold ({current_request_threshold}) for Secret Key reconstruction Not reached! ({approved_approvers_count} of {approvers_count} approved)'})
        return jsonify({'error': 'Invalid action.'}), 400 

    # GET request display logic
    pending_approvers = approvers_count - approved_approvers_count
    approval_info = f'{approved_approvers_count}/{approvers_count} approvers approved. {pending_approvers} pending.'
    display_message = ''
    reconstructed_secret_for_display = None 
    current_request_status_display = target_request.requestStatus

    if current_request_status_display == 'expired' or (is_expired_for_approval and current_request_status_display != 'approved'):
        display_message = 'This PAM request has expired. You can create a new request.'
        if target_request.requestStatus != 'expired': # Ensure DB reflects this
             target_request.requestStatus = 'expired'
             db.session.commit()
        current_request_status_display = 'expired'
    elif current_request_status_display == 'approved':
        display_message = 'Request already approved.'
        if approved_approvers_count >= current_request_threshold: # Check against specific request's threshold
            secret_shares = [approver.approver_secret_share for approver in approved_approvers_records if approver.approver_secret_share]
            if len(secret_shares) >= current_request_threshold:
                reconstructed_val_display = PAM.reconstruct_secret_from_base64_shares(secret_shares)
                if isinstance(reconstructed_val_display, bytes):
                    try: reconstructed_secret_for_display = reconstructed_val_display.decode('utf-8')
                    except UnicodeDecodeError: reconstructed_secret_for_display = str(reconstructed_val_display)
                elif isinstance(reconstructed_val_display, str): reconstructed_secret_for_display = reconstructed_val_display
                else: reconstructed_secret_for_display = str(reconstructed_val_display)

                if reconstructed_secret_for_display != secret_from_db:
                    display_message += " However, there was an issue retrieving the secret for display."
                    reconstructed_secret_for_display = "Error displaying secret" 
            else:
                 display_message += " However, could not retrieve necessary shares for display."
        else: 
            display_message += " However, inconsistency in approval count detected."
    elif approved_approvers_count >= current_request_threshold:
         display_message = 'Approvals threshold met. Ready for secret reconstruction.'
    else: 
        display_message = 'Waiting for more approvers...'

    return render_template('approval_status.html',
                           approval_info=approval_info,
                           message=display_message,
                           reconstructed_secret=reconstructed_secret_for_display, 
                           threshold=current_request_threshold, # Pass the specific request's threshold
                           expiration_time=approval_expiration_time_iso,
                           request_status=current_request_status_display, 
                           request_id=target_request.id,
                           pam_expired=is_expired_for_approval,
                           username=username, email=email, user_id=current_user_id, user_role=user_role)

@app.route('/success', methods = ['GET'])
def approval_success():
    return render_template('success.html')

@app.route('/enterSecretKey/<int:request_id>', methods=['GET', 'POST'])
@oidc.require_login
def process_secret_key(request_id):
    current_user_id = session.get('oidc_auth_profile', {}).get('sub')
    username = session.get('oidc_auth_profile', {}).get('name')
    email = session.get('oidc_auth_profile', {}).get('email')
    user_role = session.get('user_role', "User")

    if not current_user_id:
        return redirect(url_for('index'))

    target_request = AccessRequest.query.filter_by(
        id=request_id,
        requestor_id=current_user_id,
        requestStatus='approved' 
    ).first()

    if not target_request:
        # flash(f"Approved PAM request ID {request_id} not found or not accessible.", "error")
        return redirect(url_for('home'))

    if request.method == 'POST':
        entered_secret_key = request.form.get('secret_key')
        if target_request.secret_key == entered_secret_key:
            access_duration = target_request.access_duration
            session['privileged_access_active_for_request_id'] = target_request.id
            session['privileged_access_user_id'] = target_request.requestor_id
            session['privileged_access_expires_at'] = (datetime.now() + timedelta(minutes=access_duration)).timestamp()
            # flash(f"Privileged access activated for {access_duration} minutes!", "success")
            return redirect(url_for('home')) 
        else:
            return render_template('enterSecretKey.html', 
                                   request_id=request_id, 
                                   error="Invalid secret key.",
                                   username=username, email=email, user_id=current_user_id, user_role=user_role)
         
    return render_template('enterSecretKey.html', 
                           request_id=request_id,
                           username=username, email=email, user_id=current_user_id, user_role=user_role)
            

@app.route('/hidden_resource', methods=['POST'])
def hidden_resource():
    entered_secret_key = request.form.get('secret_key')

    print (f"ENTERED SECRET MESSAGE: {entered_secret_key}")

    latest_approved_request = AccessRequest.query.filter_by(requestStatus='approved').order_by(AccessRequest.id.desc()).first()

    if latest_approved_request and latest_approved_request.secret_key:
        secret_message = latest_approved_request.secret_key
        print(f"SECRET MESSAGE from DB (Request ID {latest_approved_request.id}): {secret_message}")

        if entered_secret_key == secret_message:
            return 'Valid'
        else:
            print("Comparison failed: Entered key does not match stored key.")
            return 'Invalid'
    else:
        print("Error: Could not find an approved request with a secret key.")
        return 'Invalid' 


@app.route('/protected_page')
def protected_page():
    latest_access_request = AccessRequest.query.order_by(AccessRequest.id.desc()).limit(1).all()  

    if latest_access_request:

        access_duration = 0

        for request in latest_access_request:
            access_duration = request.access_duration

            current_time = datetime.now()
            
            expiration_time = current_time + timedelta(minutes=access_duration)

            return render_template('protectedPage.html', expiration_time=expiration_time)

    else:
        print("No PAM Requests Found") 
        return "No REQUESTS FOUND!"

@oidc.require_login
@app.route('/viewAccessRequests')
def view_access_requests():
    access_requests = AccessRequest.query.all()
    approvers = Approver.query.all()
    requestor_id = session['oidc_auth_profile'].get('sub')
    print(requestor_id)

    return render_template('viewAccessRequests.html', access_requests=access_requests, approvers = approvers)

@oidc.require_login
@app.route('/testing')
def testApproval():
    #extract the approver's details
    if 'oidc_auth_profile' in session:
        auth_profile = session['oidc_auth_profile']
        username = auth_profile.get('name')
        email = auth_profile.get('email')
        user_id = auth_profile.get('sub')
        user_roles = extract_user_role(oidc,keycloak_openid) # Ensure this function returns a list
        user_role = user_roles[0] if user_roles else None # Get the first role

    #check if the user is part of the approvers group
    if user_role not in ["Security Analyst", "Branch Manager"]:  # Adjust roles as needed
        # Optionally, you might want to show an error page or just redirect home
        # return "<h1>Unauthorized: Approver role required.</h1>", 403
        return redirect(url_for('home')) # Redirecting home might be less confusing than revoking token

    # Retrieve the latest single access request to display details
    # Ideally, this should be filtered for requests specifically assigned to this approver
    # and are still in a 'pending' state. For this fix, we take the latest overall.
    access_request_to_approve = AccessRequest.query.order_by(AccessRequest.id.desc()).first()

    # Note: The secret share is typically sent via email and entered by the approver on the page,
    # so we don't necessarily need to fetch it here unless for display/verification purposes.

    return render_template('apprPage.html', 
                           access_request=access_request_to_approve, # Pass single request object
                           username=username, email=email, 
                           user_id=user_id, user_role=user_role)


@app.route('/approve_request', methods=['POST'])
def approve_request():
    if request.method == 'POST':
        data = request.json

        # Extract details from the request
        action = data.get('action')
        approver_id = data.get('approverId')
        secret_share = data.get('secretShare') #retrieve the secret share entered by the approver
        request_id = data.get('requestId') # Get the specific request ID from the payload

        if not request_id:
            return jsonify({'error': 'Request ID is missing.'}), 400

        # Optional: Verify the AccessRequest itself exists and is in a state to be approved
        access_request_item = AccessRequest.query.filter_by(id=request_id).first()
        if not access_request_item:
            return jsonify({'error': f'Access Request with ID {request_id} not found.'}), 404
        # Optionally, check access_request_item.requestStatus here

        approver = Approver.query.filter_by(approverID=approver_id, request_id=request_id).first()

        if approver:
            # Only update if the action is 'approve' and a secret share is provided
            if action == 'approve' and secret_share:
                 approver.approver_action = 'approved'
                 # Store the share entered by the approver.
                 # Ensure this matches the share originally sent. Security consideration: validate share format/origin if possible.
                 approver.approver_secret_share = secret_share
                 db.session.commit()
                 print(f"Approver {approver_id} approved request {approver.request_id} with share.")
                 return jsonify({'message': 'Request Approved!'}), 200
            elif action == 'reject': # Handle rejection if needed
                 approver.approver_action = 'rejected'
                 db.session.commit()
                 print(f"Approver {approver_id} rejected request {approver.request_id}.")
                 return jsonify({'message': 'Request Rejected!'}), 200
            else:
                 return jsonify({'error': 'Invalid action or missing secret share for approval.'}), 400
        else:
            print(f"Error: Could not find Approver record for Approver ID {approver_id} and Request ID {request_id}")
            return jsonify({'error': f'Approver record not found for Approver ID {approver_id} on Request ID {request_id}.'}), 404

    return jsonify({'error': 'Invalid Request Method'}), 405






@app.route('/simulate_ml',methods=['POST'])
def simulate():
    data = request.json
    processed = prepare_features_for_prediction(data)
    score = get_anomaly_score(processed)
    prediction = get_anomaly_prediction(processed)
    if hasattr(score, 'item'):
        prediction = prediction.item()
    return jsonify({'anomaly_score': score , 'prediction': prediction})
    



@app.route('/anomalies')
@oidc.require_login
def anomalies_dashboard():
    auth_profile = session.get('oidc_auth_profile', {})
    user_role = session.get('user_role', "User")

    # Role-based access (optional, but good practice for SIEM features)
    # if user_role not in ["Policy Administrator", "Security Viewer", "Admin"]: # Adjust as needed
    #     flash("You are not authorized to view the anomaly dashboard.", "warning")
    #     return redirect(url_for('home'))

    parent_dir = os.path.join(APP_DIR, os.pardir)
    access_decisions_file = os.path.join(parent_dir, 'access_decision.json')
    access_requests_file = os.path.join(parent_dir, 'access_requests.json')

    all_decisions = []
    if os.path.exists(access_decisions_file):
        try:
            with open(access_decisions_file, 'r') as f:
                    all_decisions = json.load(f)
            if not isinstance(all_decisions, list):
                    all_decisions = []
        except json.JSONDecodeError:
            print(f"Error decoding {access_decisions_file}")
            all_decisions = []

    all_requests_data = []
    if os.path.exists(access_requests_file):
        try:
            with open(access_requests_file, 'r') as f:
                    all_requests_data = json.load(f)
            if not isinstance(all_requests_data, list):
                    all_requests_data = []
        except json.JSONDecodeError:
            print(f"Error decoding {access_requests_file}")
            all_requests_data = []
            
    # Create a dictionary of access requests for quick lookup
    requests_map = {req.get('ID'): req for req in all_requests_data if isinstance(req, dict)}

    detected_anomalies = []
    for decision in all_decisions:
        if not isinstance(decision, dict): continue

        anomaly_prob = None
        trust_details = decision.get('trust_score_details', {})
        
        # Check for anomaly_prob at the root of trust_score_details or within segments
        if 'anomaly_prob' in trust_details:
            anomaly_prob = trust_details.get('anomaly_prob')
        elif 'segments' in trust_details and isinstance(trust_details['segments'], dict) and 'anomaly_prob' in trust_details['segments']:
            anomaly_prob = trust_details['segments'].get('anomaly_prob')

        if anomaly_prob is not None:
            try:
                anomaly_prob_float = float(anomaly_prob)
                if anomaly_prob_float > ANOMALY_DISPLAY_THRESHOLD:
                    anomaly_entry = {
                        'timestamp': decision.get('timestamp'), # Decision timestamp
                        'request_ID': decision.get('request_ID'),
                        'user_id': decision.get('user_id'),
                        'anomaly_prob': anomaly_prob_float,
                        'user_trust_score': decision.get('user_trust_score'),
                        'access_decision_val': decision.get('access_decision')
                    }
                    
                    # Add contextual info from access_requests.json
                    original_request = requests_map.get(anomaly_entry['request_ID'])
                    if original_request:
                        anomaly_entry['resource_requested'] = original_request.get('resource_requested')
                        anomaly_entry['location'] = original_request.get('location')
                        anomaly_entry['device_OS'] = original_request.get('device_OS')
                        anomaly_entry['request_time'] = original_request.get('access_request_time')
                    else:
                        anomaly_entry['resource_requested'] = 'N/A'
                        anomaly_entry['location'] = 'N/A'
                        anomaly_entry['device_OS'] = 'N/A'
                        anomaly_entry['request_time'] = 'N/A'
                        
                    detected_anomalies.append(anomaly_entry)
            except ValueError:
                print(f"Could not convert anomaly_prob '{anomaly_prob}' to float for request ID {decision.get('request_ID')}")
                continue
    
    # Sort anomalies by decision timestamp (most recent first)
    detected_anomalies.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

    return render_template('anomalies.html', 
                           anomalies=detected_anomalies,
                           threshold=ANOMALY_DISPLAY_THRESHOLD,
                           username=auth_profile.get('name'),
                           email=auth_profile.get('email'),
                           user_id=auth_profile.get('sub'),
                           user_role=user_role)







if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True,use_reloader=False)