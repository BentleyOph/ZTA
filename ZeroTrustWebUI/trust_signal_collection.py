'''
Functions related to collecting trust signals, processing them and storing them in json files 

'''

'''
HANDLING PROCESSING OF AUTH_DATA
'''

import json
import os



AUTH_DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'auth_data.json')
EVENTS_DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'events.json')


def calculate_sign_in_risk(auth_data):
    """
This function calculates the sign-in success ratio for each user based on their authentication data.
It uses a Markov Chain approach to predict the next success ratio based on the user's previous success ratios.
The function takes a list of authentication data entries, each containing user_id, auth_status, and other relevant information.
The function returns a dictionary containing the user_id as keys and their corresponding sign-in success ratio history as values.
"""
    user_dict = {} # will hold the success and failure counts for each user
    sign_in_success_ratio_map = {} # will hold the sign-in success ratio for each user
    user_chain = {} # will hold the Markov Chain for each user

    # Initialize user_chain for each user_id
    for entry in auth_data:
        user_id = entry['user_id']
        user_chain[user_id] = [0]  # Assuming starting sign-in risk

    # Iterate through auth_data to compute sign-in success ratio for each user_id
    for entry in auth_data:
        user_id = entry['user_id']
        auth_status = entry['auth_status']

        if user_id not in user_dict:
            user_dict[user_id] = {'success_count': 0, 'failure_count': 0}

        # Update success or failure count for each user
        if auth_status == 1:
            user_dict[user_id]['success_count'] += 1
        else:
            user_dict[user_id]['failure_count'] += 1

        # Calculate the sign-in success ratio based on the success and failure counts
        success_count = user_dict[user_id]['success_count']
        failure_count = user_dict[user_id]['failure_count']
        total_count = success_count + failure_count

        current_ratio = 0.0 # Default if no history
        if total_count > 0:
            current_ratio = success_count / total_count
        
        sign_in_success_ratio_map[user_id] = current_ratio

        # Update Markov Chain for each user
        user_chain[user_id].append(sign_in_success_ratio_map[user_id])

    return user_chain # Return the history chain

def predict_sign_in_risk(user_chain, current_sign_in_success_ratio_map):
    """
    This function predicts the next sign-in success ratio for each user based on the transition probabilities in their Markov Chain.
    It takes the user_chain and current_sign_in_success_ratio_map as inputs and returns a dictionary with user_id as keys and predicted success ratio as values.
    """
    # Predict the next sign-in success ratio based on the transition probabilities
    predicted_sign_in_success_ratio = {}

    for user_id, chain in user_chain.items():
        if len(chain) > 1:
            transition_prob = chain[-1] - chain[-2]  # Difference between last two values
            current_ratio = current_sign_in_success_ratio_map.get(user_id, 0.0) # Get current or default
            predicted_ratio = current_ratio + transition_prob
            # Clamp the prediction between 0 and 1
            predicted_sign_in_success_ratio[user_id] = max(0.0, min(1.0, predicted_ratio))
        else:
             predicted_sign_in_success_ratio[user_id] = current_sign_in_success_ratio_map.get(user_id, 0.5) # Use current if no history


    return predicted_sign_in_success_ratio

def process_events(events_data):
    cleaned_data = []

    for event in events_data:
        if event['user_id'] is not None:  # Skip entries with null user_id
            cleaned_event = {
                'time': event.get('time', None),
                'type': event.get('type', None),
                'user_id': event.get('user_id', None),
                'ip_address': event.get('ip_address', None),
                'auth_type': event.get('auth_type', None),
                'auth_status': 1 if event.get('type') == 'LOGIN' else 0
            }

            # Skip records not matching criteria
            if cleaned_event['auth_status'] == 0 and event.get('type') != 'LOGIN_ERROR':
                continue

            cleaned_data.append(cleaned_event)

    # Update auth_data with calculated sign-in success ratio
    auth_data = cleaned_data[:]
    user_chain = calculate_sign_in_risk(auth_data) # returns a dictionary with user_id as keys and their corresponding success ratio history

    # Update sign-in success ratio for each user in auth_data
    for entry in auth_data:
        user_id = entry['user_id']
        if user_id in user_chain and user_chain[user_id]:
             entry['sign_in_success_ratio'] = user_chain[user_id][-1] # Get the latest calculated ratio
        else:
             entry['sign_in_success_ratio'] = 0.5 # Default if no history

    # Predict the next sign-in success ratio
    current_sign_in_success_ratio_map = {entry['user_id']: entry['sign_in_success_ratio'] for entry in auth_data if entry['user_id'] is not None}
    predicted_sign_in_success_ratio = predict_sign_in_risk(user_chain, current_sign_in_success_ratio_map) # returns a dictionary with user_id as keys and predicted success ratio as values

    # Blend the predicted and current sign-in success ratio
    for entry in auth_data:
        user_id = entry['user_id']
        if user_id in predicted_sign_in_success_ratio:
            # Blend current actual ratio with the prediction
            entry['sign_in_success_ratio'] = (entry['sign_in_success_ratio'] + predicted_sign_in_success_ratio[user_id]) / 2
            # Ensure blended value is still within 0-1 range
            entry['sign_in_success_ratio'] = max(0.0, min(1.0, entry['sign_in_success_ratio']))

    file_path = AUTH_DATA

    try:
        existing_data = []
        new_id = 1

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                existing_data = json.load(file)
                if existing_data:
                    # Ensure last_entry is a dictionary and has 'ID'
                    last_entry = existing_data[-1]
                    if isinstance(last_entry, dict):
                        new_id = last_entry.get('ID', 0) + 1
                    else:
                        # Handle case where last_entry might not be a dict (e.g., corrupted file)
                        # Or simply count existing entries if ID logic is complex
                        new_id = len(existing_data) + 1 
                        print(f"Warning: Last entry in {file_path} is not a dictionary. Recalculating new_id based on length.")


        # Create a set of (time, user_id) tuples for quick lookup of existing events.
        # This avoids adding exact duplicate processed events if process_events
        # is called with data that has already been processed and stored.
        existing_event_signatures = set()
        if existing_data:
            for entry in existing_data:
                entry_time = entry.get('time')
                entry_user_id = entry.get('user_id')
                if entry_time is not None and entry_user_id is not None:
                    existing_event_signatures.add((entry_time, entry_user_id))

        auth_data_to_add = []
        # Iterate over the current batch of processed events (auth_data)
        for event_to_consider in auth_data: # auth_data contains the newly processed events
            event_time = event_to_consider.get('time')
            event_user_id = event_to_consider.get('user_id')

            # An event must have time and user_id to be considered for de-duplication
            if event_time is not None and event_user_id is not None:
                current_event_signature = (event_time, event_user_id)
                if current_event_signature not in existing_event_signatures:
                    auth_data_to_add.append(event_to_consider)
            else:
                # If an event lacks time or user_id, it cannot be reliably de-duplicated
                # by this signature method. Add it, but log a warning.
                # Consider if such events should be filtered earlier or handled differently.
                auth_data_to_add.append(event_to_consider)
                print(f"Warning: Event missing time or user_id, added without de-duplication check: {event_to_consider}")

        for i, event in enumerate(auth_data_to_add, start=new_id):
            event['ID'] = i
            existing_data.append(event)

        with open(file_path, 'w') as file:
            json.dump(existing_data, file, indent=4)

    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error occurred while handling the JSON file: {e}")

    except IOError as e:
        print(f"Error occurred while writing JSON data: {e}")


def load_events_data(file_path):
    try:
        with open(file_path, 'r') as file:
            events_data = json.load(file)
        return events_data
    except FileNotFoundError:
        print(f"File '{file_path}' not found.")
        return None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON file: {e}")
        return None

'''

HANDLING PROCESSING AND STORAGE OF EVENTS DATA

'''

def store_keycloak_events(keycloak_admin):
    query_params = {
        "dateFrom": "2025-01-01",
        "dateTo": "2025-12-31",
        "max": 10000,
    }

    events_data = keycloak_admin.get_events(query=query_params)
    print(f"Retrieved {len(events_data)} events from Keycloak")
    print(f'The last 5 events are: {events_data[-5:]}')
    cleaned_data = []

    for event in events_data:
        cleaned_event = {
            'time': event.get('time', None),
            'type': event.get('type', None),
            'user_id': event.get('userId', None),
            'ip_address': event.get('ipAddress', None)
        }

        if 'details' in event:
            details = event['details']
            cleaned_event['auth_type'] = details.get('auth_type', None)
            cleaned_event['token_id'] = details.get('token_id', None)

        cleaned_event['session_id'] = event.get('sessionId', None)

        cleaned_data.append(cleaned_event)
    
    # Use absolute path to events.json in the project root directory
    file_path = EVENTS_DATA
    print(f"Writing events to: {file_path}")

    try:
        existing_data = []
        new_id = 1

        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                try:
                    existing_data = json.load(file)
                    if existing_data:
                        last_entry = existing_data[-1]
                        new_id = last_entry.get('ID', 0) + 1
                    print(f"Loaded {len(existing_data)} existing events")
                except json.JSONDecodeError:
                    print("Error decoding existing file, starting with empty data")
                    existing_data = []

        # Count new events for logging
        new_events_count = 0
        
        for i, event in enumerate(cleaned_data, start=new_id):
            event_exists = False
            for existing_event in existing_data:
                if (event.get('time') == existing_event.get('time') and 
                    event.get('user_id') == existing_event.get('user_id')):
                    event_exists = True
                    break

            if not event_exists:
                event['ID'] = i
                existing_data.append(event)
                new_events_count += 1

        # Only write file if there are actual changes
        if new_events_count > 0:
            with open(file_path, 'w') as file:
                json.dump(existing_data, file, indent=4)
            print(f"Added {new_events_count} new events to events.json")
        else:
            print("No new events to add")

    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"Error occurred while handling the JSON file: {e}")
        # Create the file with initial data if it doesn't exist
        if isinstance(e, FileNotFoundError):
            try:
                os.makedirs(os.path.dirname(file_path), exist_ok=True)
                with open(file_path, 'w') as file:
                    for i, event in enumerate(cleaned_data, start=1):
                        event['ID'] = i
                    json.dump(cleaned_data, file, indent=4)
                print(f"Created new events.json file with {len(cleaned_data)} events")
            except IOError as write_error:
                print(f"Failed to create new events.json file: {write_error}")
    except IOError as e:
        print(f"Error occurred while writing JSON data: {e}")
        
    return len(cleaned_data)

#get the latest access request data for a particular user_id

def get_latest_access_request(user_id, access_requests):
    with open(access_requests, 'r') as file:
        data = json.load(file)

    latest_request = None
    for request in data:
        if request['user_id'] == user_id:
            if latest_request is None or request['access_request_time'] > latest_request['access_request_time']:
                latest_request = request

    return latest_request

#get the latest auth data for the particular user_id
def get_latest_auth_data(user_id, auth_data):
    with open(auth_data, 'r') as file:
        data = json.load(file)

    latest_data = None
    for entry in data:
        if entry['user_id'] == user_id:
            if latest_data is None or entry['time'] > latest_data['time']:
                latest_data = entry

    return latest_data

#get user identity information
def get_user_identity_data_by_id(user_id, user_data_file):
    with open(user_data_file, 'r') as file:
        user_data = json.load(file)

    for user in user_data:
        if user['user_id'] == user_id:
            return user

    return None  # Return None if user_id not found

