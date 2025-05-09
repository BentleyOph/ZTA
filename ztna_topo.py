# /home/user/bentleyoph-zta/ztna_topology.py
from mininet.net import Mininet
from mininet.node import Host
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink # For potentially setting link characteristics later

# --- Configuration ---
PROJECT_BASE_DIR = '/home/bento/projects/ZTA/ZeroTrustArchitecture' # IMPORTANT: Change if your project path is different
PYTHON_EXEC = 'python3' # or 'python' if that's your default python3

# Define IP addresses for our services
IP_CONFIG = {
    'ap': '10.0.0.1',
    'te': '10.0.0.2',
    'pe': '10.0.0.3',
    'webui': '10.0.0.4',
    'keycloak': '10.0.0.5', # If running Keycloak inside Mininet (more complex)
    'user1': '10.0.0.10',
    'resource1': '10.0.0.20', # A sample protected resource
}

# Define ports for our services
PORT_CONFIG = {
    'ap': 5001,
    'te': 5002,
    'pe': 5003,
    'webui': 5000, # Flask default
    'keycloak': 8080,
    'resource1': 80, # HTTP server for the resource
}

def ztnaNet():
    "Create a Mininet network for ZTNA components."
    # We are not adding an SDN controller yet, Mininet will use its default controller
    # which provides basic L2 switching.
    net = Mininet(link=TCLink, waitConnected=True)

    info('*** Adding hosts\n')
    h_ap = net.addHost('h_ap', ip=f"{IP_CONFIG['ap']}/24")
    h_te = net.addHost('h_te', ip=f"{IP_CONFIG['te']}/24")
    h_pe = net.addHost('h_pe', ip=f"{IP_CONFIG['pe']}/24")
    h_webui = net.addHost('h_webui', ip=f"{IP_CONFIG['webui']}/24")
    
    h_user1 = net.addHost('h_user1', ip=f"{IP_CONFIG['user1']}/24")
    h_res1 = net.addHost('h_res1', ip=f"{IP_CONFIG['resource1']}/24")

    # Optional: Keycloak host if you decide to run it inside Mininet
    # h_keycloak = net.addHost('h_keycloak', ip=f"{IP_CONFIG['keycloak']}/24")

    info('*** Adding switch\n')
    s1 = net.addSwitch('s1')

    info('*** Creating links\n')
    net.addLink(h_ap, s1)
    net.addLink(h_te, s1)
    net.addLink(h_pe, s1)
    net.addLink(h_webui, s1)
    net.addLink(h_user1, s1)
    net.addLink(h_res1, s1)
    # if 'h_keycloak' in locals(): net.addLink(h_keycloak, s1)


    info('*** Starting network\n')
    net.start() # This starts the default controller as well

    # --- Start ZTNA component services on their respective hosts ---
    info('*** Starting ZTNA components (as background processes)\n')

    # AccessProxy - Will become a Flask app
    # For now, we'll just have it ready to be a Flask app.
    # We'll modify AccessProxy.py later.
    # h_ap.cmd(f'{PYTHON_EXEC} {PROJECT_BASE_DIR}/AccessProxy.py &> {PROJECT_BASE_DIR}/ap.log &')

    # TrustEngine - Will become a Flask app
    # h_te.cmd(f'{PYTHON_EXEC} {PROJECT_BASE_DIR}/TrustEngine.py &> {PROJECT_BASE_DIR}/te.log &')

    # PolicyEngine - Will become a Flask app
    # h_pe.cmd(f'{PYTHON_EXEC} {PROJECT_BASE_DIR}/PolicyEngine.py &> {PROJECT_BASE_DIR}/pe.log &')

    # WebUI - Already a Flask app, adjust host and port for Mininet
    # Make sure your app.py can accept --host and --port arguments or configure it directly
    webui_cmd = (
        f'cd {PROJECT_BASE_DIR}/ZeroTrustWebUI && '
        f'{PYTHON_EXEC} app.py '
        f'--host {IP_CONFIG["webui"]} --port {PORT_CONFIG["webui"]} ' # Or 0.0.0.0 to listen on all interfaces of the host
        f'&> {PROJECT_BASE_DIR}/webui.log &'
    )
    h_webui.cmd(webui_cmd)
    info(f'  WebUI starting on http://{IP_CONFIG["webui"]}:{PORT_CONFIG["webui"]}\n')

    # Start a simple HTTP server on the resource host for testing
    h_res1.cmd(f'{PYTHON_EXEC} -m http.server {PORT_CONFIG["resource1"]} --bind {IP_CONFIG["resource1"]} &> {PROJECT_BASE_DIR}/resource1.log &')
    info(f'  Resource1 server starting on http://{IP_CONFIG["resource1"]}:{PORT_CONFIG["resource1"]}\n')

    # If running Keycloak inside Mininet:
    # You'd need a more complex command here to start Keycloak, potentially involving Docker within Mininet host
    # or a native Keycloak installation accessible by the Mininet host.
    # For now, assume Keycloak is running *outside* Mininet and is accessible by the host machine/VM.

    info('*** Network is up. You can access services using their Mininet IPs.\n')
    info('*** Example: Access WebUI from your VM\'s browser (if routing/NAT allows) or from h_user1 xterm.\n')
    info('*** To open xterm on a host: mininet> xterm h_user1\n')

    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    ztnaNet()