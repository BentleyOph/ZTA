'''

Class that extends the p2pnetwork class to add application specific implementation Details 
Handles how communication happens between the access proxy, trust engine, and policy engine.
Uses peer to peer communication without involvement of a centralized server for establishing connections

'''
import datetime
from p2pnetwork.node import Node
import yaml
import ZeroTrustWebUI.TrustAlgorithm as ta
from ZeroTrustWebUI.trust_signal_collection import *
import time 

class Networking(Node):
    #Define a dictionary of the node roles based on their node.id attributes
    NODE_ROLE = {
        '1': 'Access Proxy Node',
        '2':'Trust Engine Node',
        '3':'Policy Engine Node',
        '4':'Web UI'
    }

    # Python class constructor to initialize the class Networking
    def __init__(self, host, port, id=None, callback=None, max_connections=0):
        super(Networking, self).__init__(host, port, id, callback, max_connections)
        print(f"\n{self.get_node_role(self.id)} STARTED on {self.host}:{self.port}")
    
    #Define a function to extract the name of a node based on it's node.id attribute
    def get_node_role(self,node_id):
        return self.NODE_ROLE.get(node_id,'UNKNOWN ROLE')
    

    def send_message_to_node(self, node_id, message):
        # Find the specific node by its ID
        target_node = None

        for node in self.all_nodes:
            if node.id == node_id:
                target_node = node
                #convert the message to a json object
                json_message = {
                    "senderID": self.id,
                    "messageContent":message
                }
                # Send the message to the specific node
                self.send_to_node(target_node, json_message)
                print(f"Message sent to: {self.get_node_role(node_id)}")
                break
        if target_node is None:
            print(f"Node {node_id} not found in inbound or outbound connections.")
    
    def message_is_from_access_proxy(self, sender_id):
        return sender_id == '1'

    def message_is_from_trust_engine(self, sender_id):
        return sender_id == '2'

    def message_is_from_policy_engine(self, sender_id):
        return sender_id == '3'
    
    def message_is_from_web_ui(self, sender_id):
        return sender_id == '4'
    

    def process_message_from_access_proxy(self, sender, message):
        print(f"Received a message from Access Proxy Node [{sender}]: {message}")
        #if this node is trust engine, check if the intent is 'request_trust_score'
        if message.get('intent') == 'request_trust_score':
            user_id = message.get('user_id')
            request_id = message.get('request_ID') # Extract the forwarded request ID

            if user_id is None or request_id is None:
                print("Error: Missing user_id or request_ID in message from Access Proxy")
                return # Stop processing

            print(f"Received a Trust Score Request From: {user_id} for Request ID: {request_id}")
            #get the trust score for this user_id using the trust algorithm
            user_trust_score = ta.calculate_overall_trust_score(user_id)
            print(f"Performing Trust Evaluation for the Subject({user_id})...")
            print(f"Subject({user_id}) Trust Score: {user_trust_score}")
            print(f"Sending the subject's trust score to Policy Engine for policy validation...")
            data = {
                'user_id': user_id,
                'request_ID': request_id, # Pass the original request ID forward again
                'intent': 'request_access_decision',
                'user_trust_score': user_trust_score
            }
            self.send_message_to_node('3',data)
    
    def make_access_decision(self,user_role, user_trust_score, sign_in_risk):
    # Load policy configuration data from YAML file
        with open('policyConfiguration.yml', 'r') as file:
            policy_configuration = yaml.safe_load(file)

        # Access specific values from the policy configuration
        admin_threshold = float(policy_configuration['adminThreshold'])
        approver_threshold = float(policy_configuration['approverThreshold'])
        security_viewer_threshold = float(policy_configuration['securityViewerThreshold'])
        sign_in_risk_threshold = float(policy_configuration['signInRiskThreshold'])

        # Initialize verdict
        verdict = 1

        # Determine access decision based on user trust score and role-specific thresholds
        if user_role == 'Approver' and user_trust_score < approver_threshold:
            verdict = 0
        elif user_role == 'Security Viewer' and user_trust_score < security_viewer_threshold:
            verdict = 0
        elif user_role == 'Policy Administrator' and user_trust_score < admin_threshold:
            verdict = 0

        # Determine access decision based on sign-in risk threshold
        if sign_in_risk < sign_in_risk_threshold:
            verdict = 0

        return verdict


    def process_message_from_trust_engine(self, sender, message):
        print(f"Received a message from Trust Engine Node [{sender}]: {message}")
        #if this node is a policy engine then check if the message intent is 'request_access_decision'
        if message.get('intent') == 'request_access_decision':
            user_id = message.get('user_id')
            user_trust_score = message.get('user_trust_score')
            original_request_id = message.get('request_ID') # Extract the original request ID

            if user_id is None or original_request_id is None or user_trust_score is None:
                 print("Error: Missing user_id, request_ID, or user_trust_score in message from Trust Engine")
                 return # Stop processing

            print(f"Received a Request for Access Decision from Trust Engine for User {user_id}, Request ID: {original_request_id}")
            print(f"Current Subject's Trust Score: {user_trust_score}")
            print(f"Checking against security policies...")
            # ... (rest of the data fetching logic remains the same) ...
            # Note: get_latest_access_request might need adjustment if it should fetch based on original_request_id instead of just user_id
            print(f"Latest Access Request for the user: {get_latest_access_request(user_id,'access_requests.json')}")
            print(f"Latest Authentication Data for the user: {get_latest_auth_data(user_id,'auth_data.json')}")
            print(f"User Identity Data: {get_user_identity_data_by_id(user_id,'user_data.json')}")

            user_identity_data = get_user_identity_data_by_id(user_id,'user_data.json')
            user_auth_data = get_latest_auth_data(user_id, 'auth_data.json')
            user_access_request = get_latest_access_request(user_id, 'access_requests.json')


             # Retrieving user_role from user_identity_data
            user_role = user_identity_data.get('user_role')

            print(f"User Role: {user_role}")

            # Retrieving sign_in_risk from user_auth_data
            sign_in_risk = user_auth_data.get('sign_in_risk')
            print(f"Sign In Risk: {sign_in_risk}")

    
            location = user_access_request.get('location', '') # Consider if this is still the correct way to get location for the specific request
            country = location.split('/')[-1]
            print(f"Country: {country}")

            file_path = 'access_decision.json'
            access_decisions = [] # Initialize empty list

            # Load existing decisions to append
            if os.path.exists(file_path):
                try:
                    with open(file_path, 'r') as file:
                        # Handle empty or invalid JSON file
                        content = file.read()
                        if content.strip():
                            access_decisions = json.loads(content)
                        else:
                            access_decisions = []
                except json.JSONDecodeError:
                    print(f"Error decoding JSON from {file_path}, starting fresh.")
                    access_decisions = []
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
                    access_decisions = [] # Start fresh on other read errors too
            verdict = self.make_access_decision(user_role,user_trust_score,sign_in_risk)

            print(f"Policy Engine Verdict: {verdict}")
             # Prepare the access decision data using the original request ID
            access_decision_data = {
                'request_ID': original_request_id, # Use the original ID with the key 'request_ID'
                'user_id': user_id,
                # 'intent': 'request_access_decision', # You might not need to store the intent here
                'user_trust_score': user_trust_score,
                'access_decision': verdict,
                'timestamp': time.time() # Add timestamp for sorting in app.py
            }

            # Append the new access decision data to the existing list
            access_decisions.append(access_decision_data)

            # Write the updated data to the JSON file BEFORE sending the message
            try:
                with open(file_path, 'w') as file:
                    json.dump(access_decisions, file, indent=4)
            except IOError as e:
                 print(f"Error writing access decision to {file_path}: {e}")
                 # Consider if you should still send the message if writing failed
                 return

            # Now send the message after ensuring data is persisted
            self.send_message_to_node('4', access_decision_data) # Send decision back to Web UI

    def process_message_from_policy_engine(self, sender, message):
        print(f"Received a message from Policy Engine Node [{sender}]: {message}")

    
    def process_message_from_web_ui(self, sender, message):
        print(f"Received an Access Request from Web UI [{sender}]: {message}")
        # Check if the 'intent' key has the value 'Access Request'
        # Use .get with a default and check the value to avoid KeyError
        if message.get('intent') == 'Access Request': # Make sure the intent string matches exactly what app.py sends
            #access request received, prepare data to send to Trust Engine(node 2)
            user_id = message.get('user_id')
            request_id = message.get('ID') # Extract the original request ID from the Web UI message

            if user_id is None or request_id is None:
                print("Error: Missing user_id or ID in message from Web UI")
                return # Stop processing if essential data is missing

            intent = 'request_trust_score'

            data = {
                'user_id': user_id,
                'request_ID': request_id, # Pass the original request ID forward using 'request_ID' key
                'intent': intent
            }
            self.send_message_to_node('2',data)
        else:
            print(f"Received message from Web UI with unexpected intent: {message.get('intent')}")

    def print_all_nodes(self):
        print("Outbound Nodes:")
        for node in self.nodes_outbound:
            print(f"Outbound Node ID: {node.id}, Host: {node.host}, Port: {node.port}")

        print("\nInbound Nodes:")
        for node in self.nodes_inbound:
            print(f"Inbound Node ID: {node.id}, Host: {node.host}, Port: {node.port}")


    # The methods below are called when events happen in the network

    def outbound_node_connected(self, node):
        node_role = self.get_node_role(node.id)
        print(f"\n{self.get_node_role(self.id)} Connected to {node_role}")
        
    def inbound_node_connected(self, node):
        print(f"\n{self.get_node_role(node.id)} Connected to {self.get_node_role(self.id)}")

    def inbound_node_disconnected(self, node):
        print(f"\n{self.get_node_role(node.id)} DISCONNECTED from {self.get_node_role(self.id)}")

    def outbound_node_disconnected(self, node):
        print(f"\n{self.get_node_role(self.id)} DISCONNECTED from {self.get_node_role(node.id)}")

    def node_message(self, node, data):
        sender_id = node.id  # Get the sender's ID
        message_content = data  # Get the message content

        if "senderID" in message_content:
            message_content = message_content["messageContent"]
            #extract other future message atributes like unique hash, and message intent

        # Process the message based on the sender's ID
        if self.message_is_from_access_proxy(sender_id):
            self.process_message_from_access_proxy(sender_id, message_content)
        elif self.message_is_from_trust_engine(sender_id):
            self.process_message_from_trust_engine(sender_id, message_content)
        elif self.message_is_from_policy_engine(sender_id):
            self.process_message_from_policy_engine(sender_id, message_content)
        elif self.message_is_from_web_ui(sender_id):
            self.process_message_from_web_ui(sender_id, message_content)
        else:
            print(f"Received a message from an unknown sender ({sender_id}): {message_content}")
        
    def node_disconnect_with_outbound_node(self, node):
        print(f"\n{self.get_node_role(self.id)} wants to disconnect with {node.id}")   
            
    def node_request_to_stop(self):
        print(f"\nStopping the {self.get_node_role(self.id)} node")

