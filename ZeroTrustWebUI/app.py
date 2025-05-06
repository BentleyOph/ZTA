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
import requests
import yaml
from Networking import Networking
from keycloak import KeycloakAdmin
from keycloak import KeycloakOpenIDConnection
import re, uuid
from keycloak_config import *
from PAM import PAM
from Keycloak_functions import *
from PAM_Mail_Notification import send_email,send_email_to_approver
from trust_signal_collection import store_keycloak_events,load_events_data,process_events
from TrustAlgorithm import prepare_features_for_prediction, get_anomaly_score
import time 

sys.path.insert(0,'..')

logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)

'''
This section below contains the configuration of the flask OIDC and the keycloak OIDC
'''

app.config['OIDC_SESSION_TYPE'] = 'null'

app.config.update({
    'SECRET_KEY': 'bzf9bctfGor9tB2rOfLdQnK3VNDxt6rx',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
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
@oidc.require_login
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

                    parent_directory = os.path.abspath(os.path.join(os.getcwd(), os.pardir))

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

                    # Define the path to the JSON file
                    parent_directory = os.path.abspath(os.path.join(os.getcwd(), os.pardir))
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

                    return render_template('home.html', username=username, email=email, user_id=user_id, user_role=user_role)
                else:
                    return "<h1>NOT AUTHORIZED!</h1>"
            else:
                return "<h1>UNAUTHORIZED [INVALID ACCESS TOKEN]!!!</h1>"
        else:
            return redirect(url_for('login'))
    except KeycloakAuthenticationError as e:
        print(f"KeycloakAuthenticationError: {e}")
        return redirect(url_for('index'))
    

# Define the path to the parent directory where the JSON file is stored
parent_directory = os.path.abspath(os.path.join(os.getcwd(), os.pardir))

# Define the path to the access_decision.json file
file_path = os.path.join(parent_directory, 'access_decision.json')

# Function to get the latest access decision data from the JSON file
def get_latest_access_decision():
    latest_decision = None
    
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            access_decisions = json.load(file)
            if access_decisions:
                latest_decision = max(access_decisions, key=lambda x: x['ID'])
    
    return latest_decision

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
    
    parent_directory = os.path.abspath(os.path.join(os.getcwd(), os.pardir))
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
    access_requests_file_path = os.path.join(os.path.abspath(os.path.join(os.getcwd(), os.pardir)), 'access_requests.json')
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
    max_wait_time = 60
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

# Function to create or update policyConfiguration.yml file
def update_policy_configurations(data):
    # Get the parent directory path
    parent_directory = os.path.abspath(os.path.join(os.getcwd(), os.pardir))
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

@app.route('/resource-1')
def display_transactions():
    # Load transactions from the JSON file
    with open('mobile_money_transactions.json', 'r') as file:
        transactions = json.load(file)
    
    return render_template('transaction_simulation.html', transactions=transactions)

@app.route('/resource-2')
def display_tokens():
    # Load tokens from JSON file
    with open('tokens.json', 'r') as file:
        tokens = json.load(file)
    
    return render_template('Fintech Access Tokens.html', tokens=tokens)

@app.route('/logging')
def access_requests():
    file_path = os.path.join(os.path.dirname(os.getcwd()), 'access_requests.json')
    
    with open(file_path, 'r') as file:
        access_requests_data = json.load(file)
    
    return render_template('logging_and_monitoring.html', access_requests=access_requests_data)



@app.route('/configurePolicies')
def configure_policies():
    # Retrieve the access duration from the database for the latest approved request ID

    latest_access_request = AccessRequest.query.order_by(AccessRequest.id.desc()).limit(1).all()  # Adjust 'limit' as needed

    if latest_access_request:

        for request in latest_access_request:
            access_duration = request.access_duration

            # Get the current time
            current_time = datetime.now()
            
            # Calculate the expiration time by adding access duration to the current time
            expiration_time = current_time + timedelta(minutes=access_duration)

            return render_template('policyConfiguration.html', expiration_time=expiration_time)

@app.route('/privilegedAccess', methods=['GET', 'POST'])
@oidc.require_login
def privilegedAccess():
    #dynamically query the keycloak API for the list of approvers to display for the requestor
    client_id = keycloak_admin.get_client_id(KEYCLOAK_CLIENT_ID)
    role_name = "Approver"
    email_addresses = get_client_role_members_emails(keycloak_admin,client_id, role_name)

    if email_addresses is None:
        email_addresses = []

    num_shares = len(email_addresses) #equal to the number of approvers

    global THRESHOLD
    if num_shares > 0: 
        THRESHOLD = math.floor(num_shares * 0.8) 
    else:
        THRESHOLD = 0 

    if request.method == 'POST':
        # Get form data
        resource_name = request.form['resource_name']
        reason_for_access = request.form['reason_for_access']
        access_duration = int(request.form['access_duration'])
        # Get the current user's ID and username from the session
        requestor_id = session['oidc_auth_profile'].get('sub')
        requestor_username = session['oidc_auth_profile'].get('preferred_username')
        # Capture the time of the request
        time_of_request = datetime.now()

        # Extract selected approvers in a list
        selected_approvers = request.form.getlist('approvers')

        num_selected_shares = len(selected_approvers)
        if num_selected_shares == 0:
             return "Please select at least one approver.", 400

        secret_key = PAM.generate_secret_message(45)
        secret_key_identifier = PAM.generate_secret_message(4) 

        secret_shares_list = PAM.generate_secret_shares(THRESHOLD, num_selected_shares, secret_key, secret_key_identifier)

        if not (1 <= access_duration <= 100):
            return "Invalid access duration. Please enter a value between 1 and 100 minutes."

        new_request = AccessRequest(
            resource_name=resource_name,
            reason_for_access=reason_for_access,
            access_duration=access_duration,
            requestor_id=requestor_id,
            requestor_username=requestor_username,
            time_of_request=time_of_request,
            requestStatus='pending',  
            secret_key=secret_key,    
        )

        db.session.add(new_request)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            print(f"Error saving access request: {e}")
            return "Error processing request.", 500

        for index, approver_email in enumerate(selected_approvers):
            approver_secret_share = secret_shares_list[index] 
            send_email_to_approver(approver_email,requestor_id,requestor_username,reason_for_access,access_duration,approver_secret_share)

            approver = Approver(
                approverID=get_user_id_by_email(keycloak_admin,approver_email),
                approverEmail=approver_email,
                request_id=new_request.id,
                approver_secret_share=approver_secret_share  
            )
            db.session.add(approver)

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            return "Error processing request.", 500

        return redirect(url_for('approval_status'))

    return render_template('privilegedAccessManagement.html',email_addresses=email_addresses)


@app.route('/approval_status', methods=['GET','POST'])
def approval_status():
    global THRESHOLD
    latest_request = AccessRequest.query.order_by(AccessRequest.id.desc()).first()

    if not latest_request:
        return render_template('no_requests.html') 

    latest_request_id = latest_request.id
    secret_from_db = latest_request.secret_key

    associated_approvers = Approver.query.filter_by(request_id=latest_request_id).all()
    approvers_count = len(associated_approvers)
    approved_approvers_records = [appr for appr in associated_approvers if appr.approver_action == 'approved']
    approved_approvers_count = len(approved_approvers_records)

    if THRESHOLD is None and approvers_count > 0:
        THRESHOLD = math.floor(approvers_count * 0.8)
    elif THRESHOLD is None:
        THRESHOLD = 0 

    if request.method == 'POST':
         data = request.json
         action = data.get('action')

         if action == 'reconstruct_secret':
            if approved_approvers_count >= THRESHOLD:
                message = 'Threshold for Approval Met! Reconstructing key...'
                secret_shares = [approver.approver_secret_share for approver in approved_approvers_records if approver.approver_secret_share] 

                if len(secret_shares) < THRESHOLD:
                     print("Error: Not enough valid shares found despite meeting approval count.")
                     return jsonify({'ERR_RECONSTRUCT': 'Could not retrieve enough valid shares.'}), 500

                reconstructed_secret_val = PAM.reconstruct_secret_from_base64_shares(secret_shares)
                reconstructed_secret_str = None
                if isinstance(reconstructed_secret_val, bytes):
                    try:
                        reconstructed_secret_str = reconstructed_secret_val.decode('utf-8')
                    except UnicodeDecodeError:
                        print("Warning: Could not decode reconstructed secret bytes to UTF-8.")
                        reconstructed_secret_str = str(reconstructed_secret_val)
                elif isinstance(reconstructed_secret_val, str):
                    reconstructed_secret_str = reconstructed_secret_val
                else:
                     print(f"Warning: Unexpected type from reconstruction: {type(reconstructed_secret_val)}")
                     reconstructed_secret_str = str(reconstructed_secret_val)

                print(f"Secret from DB: {secret_from_db}")
                print(f"Reconstructed Secret (Decoded): {reconstructed_secret_str}")

                if reconstructed_secret_str == secret_from_db:
                    latest_request.requestStatus = 'approved'
                    db.session.commit()
                    return jsonify({'reconstructed_secret': reconstructed_secret_str, 'message': 'Secret reconstructed successfully.'})
                else:
                    print("Error: Reconstructed secret does not match the one stored for this request.")
                    return jsonify({'ERR_RECONSTRUCT': 'Secret reconstruction failed or mismatch.'}), 500

            else: 
                 return jsonify({'ERR_THRESH': f'Minimum Threshold ({THRESHOLD}) for Secret Key reconstruction Not reached! ({approved_approvers_count} approved)'})
         else:
             return jsonify({'message': 'Action processed or not applicable.'})

    pending_approvers = approvers_count - approved_approvers_count
    approval_info = f'{approved_approvers_count}/{approvers_count} approvers approved, {pending_approvers} pending'
    message = ''
    reconstructed_secret_str = None 

    APPROVAL_TIME = 10 
    current_time = datetime.now()
    expiration_time = latest_request.time_of_request + timedelta(minutes=APPROVAL_TIME) 

    if latest_request.requestStatus == 'approved':
        message = 'Request already approved.'
        if approved_approvers_count >= THRESHOLD:
            secret_shares = [approver.approver_secret_share for approver in approved_approvers_records if approver.approver_secret_share]
            if len(secret_shares) >= THRESHOLD:
                reconstructed_secret_val = PAM.reconstruct_secret_from_base64_shares(secret_shares)
                if isinstance(reconstructed_secret_val, bytes):
                    try:
                        reconstructed_secret_str = reconstructed_secret_val.decode('utf-8')
                    except UnicodeDecodeError:
                        reconstructed_secret_str = str(reconstructed_secret_val)
                elif isinstance(reconstructed_secret_val, str):
                    reconstructed_secret_str = reconstructed_secret_val
                else:
                    reconstructed_secret_str = str(reconstructed_secret_val)

                if reconstructed_secret_str != secret_from_db:
                    print("Warning: Reconstructed secret in approved state doesn't match DB record.")
                    message = "Request approved, but encountered an issue retrieving the secret."
                    reconstructed_secret_str = "Error retrieving secret" 
            else:
                 print("Warning: Request approved but not enough shares found for reconstruction.")
                 message = "Request approved, but could not retrieve necessary shares."
                 reconstructed_secret_str = None
        else:
             print("Warning: Request approved but approval count is below threshold.")
             message = "Request approved, but inconsistency detected."
             reconstructed_secret_str = None

    elif approved_approvers_count >= THRESHOLD:
         message = 'Approvals threshold met. Ready for secret reconstruction.'

    else: 
        message = 'Waiting for more approvers...'


    return render_template('approval_status.html',
                           approval_info=approval_info,
                           message=message,
                           reconstructed_secret=reconstructed_secret_str, 
                           threshold=THRESHOLD,
                           expiration_time=expiration_time,
                           request_status=latest_request.requestStatus, 
                           request_id=latest_request_id) 


@app.route('/success', methods = ['GET'])
def approval_success():
    return render_template('success.html')

@app.route('/enterSecretKey', methods=['GET', 'POST'])
def process_secret_key():

    if request.method == 'POST':
        entered_secret_key = request.form.get('secret_key')

        if entered_secret_key:
            response = requests.post('http://127.0.0.1:5000/hidden_resource',data={'secret_key': entered_secret_key})

            if response.text == 'Valid':
                return redirect('/configurePolicies')
            else:
                return "INVALID SECRET KEY"
            
    return render_template('enterSecretKey.html')

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
    if user_role != "Approver":
        # Optionally, you might want to show an error page or just redirect home
        # return "<h1>Unauthorized: Approver role required.</h1>", 403
        return redirect(url_for('home')) # Redirecting home might be less confusing than revoking token

    # Retrieve the latest access request to display details
    # You might want to filter requests relevant to this approver if needed
    access_requests = AccessRequest.query.order_by(AccessRequest.id.desc()).limit(1).all()

    # Note: The secret share is typically sent via email and entered by the approver on the page,
    # so we don't necessarily need to fetch it here unless for display/verification purposes.

    return render_template('apprPage.html', access_requests=access_requests, username=username, email=email, user_id=user_id, user_role=user_role)


@app.route('/approve_request', methods=['POST'])
def approve_request():
    if request.method == 'POST':
        data = request.json

        # Extract details from the request
        action = data.get('action')
        approver_id = data.get('approverId')
        secret_share = data.get('secretShare') #retrieve the secret share entered by the approver

        # Find the latest request associated with this approver
        # Assuming one approver might have multiple pending requests, target the latest one
        # Or, you might need a request_id passed from the frontend to be specific
        latest_request = AccessRequest.query.order_by(AccessRequest.id.desc()).first()
        if not latest_request:
             return jsonify({'error': 'No pending access requests found.'}), 404

        approver = Approver.query.filter_by(approverID=approver_id, request_id=latest_request.id).first()

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
            print(f"Error: Could not find Approver record for ID {approver_id} and Request ID {latest_request.id}")
            return jsonify({'error': 'Approver record not found for this request.'}), 404

    return jsonify({'error': 'Invalid Request Method'}), 405






@app.route('/simulate_ml',methods=['POST'])
def simulate():
    data = request.json
    processed = prepare_features_for_prediction(data)
    score = get_anomaly_score(processed)
    return jsonify({'anomaly_score': score})











if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True,use_reloader=False)