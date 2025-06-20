# Zero Trust Architecture (ZTA) Platform

![Project Banner](https://img.shields.io/badge/Project-Zero%20Trust%20Platform-blue)
![Python Version](https://img.shields.io/badge/Python-3.9%2B-brightgreen)
![Framework](https://img.shields.io/badge/Framework-Flask-red)
![Auth](https://img.shields.io/badge/Authentication-Keycloak-yellow)

This project is an implementation of a Zero Trust Architecture (ZTA) platform designed to provide secure, dynamic, and context-aware access control to protected resources. The system moves beyond traditional perimeter-based security by continuously evaluating trust and enforcing granular policies for every access request.

It integrates a dynamic **Trust Engine**, a configurable **Policy Engine**, and a **Flask-based Web UI**, all orchestrated through a peer-to-peer communication network. Authentication and identity management are handled by **Keycloak**, while a sophisticated **Privileged Access Management (PAM)** module provides secure, just-in-time access using Shamir's Secret Sharing for multi-party approval.

---

## Core Features

-   **Dynamic Trust Scoring:** Calculates a real-time trust score for each user based on multiple signal categories:
    -   **User Identity:** Verifies user attributes like email verification and multi-factor authentication (MFA/TOTP) status.
    -   **Authentication History:** Analyzes sign-in success ratios and authentication methods.
    -   **User Experience:** Factors in account tenure as a measure of established trust.
    -   **Contextual Signals:** Assesses risk from geolocation, device type, OS, and time of access.
-   **Machine Learning-Powered Anomaly Detection:** Utilizes a pre-trained **Isolation Forest** model to detect anomalous access patterns and adjust trust scores accordingly.
-   **Dynamic Policy Enforcement:** Enforces access decisions using a flexible, YAML-based policy engine. Policies can be configured based on user roles, trust score thresholds, and resource sensitivity.
-   **Just-in-Time (JIT) Privileged Access Management (PAM):**
    -   Allows users to request temporary, elevated access to all resources.
    -   Implements **Shamir's Secret Sharing** to split an access secret among multiple approvers.
    -   Requires a configurable threshold of approvers to reconstruct the secret, ensuring multi-party authorization for sensitive operations.
-   **Centralized Identity & Access Management (IAM):** Integrates with **Keycloak** via OpenID Connect (OIDC) for robust user authentication and role management.
-   **Modular, Peer-to-Peer Architecture:** The Trust Engine, Policy Engine, and Web UI operate as independent nodes that communicate over a P2P network, promoting scalability and resilience.
-   **Comprehensive Web Interface:** A Flask-based UI provides:
    -   A user-facing portal for accessing resources.
    -   An administrative dashboard for configuring security policies.
    -   A monitoring view for observing access logs and security events.
    -   A full workflow for requesting, approving, and utilizing privileged access.

---

## System Architecture

The platform consists of several key components that work together to enforce Zero Trust principles:

1.  **ZeroTrustWebUI (Flask Application):** The central hub for user interaction. It serves as the Policy Administration Point (PAP) and Policy Enforcement Point (PEP). Users log in, request resource access, and manage PAM requests through this interface. It communicates with the backend engines.

2.  **Trust Engine (`TrustEngine.py`):** The brain of the trust assessment process. It receives access requests from the UI, gathers all relevant trust signals (from data files emulating various sources), calculates the overall trust score, and forwards the assessment to the Policy Engine.

3.  **Policy Engine (`PolicyEngine.py`):** The decision-maker. It receives the trust score and contextual data from the Trust Engine, evaluates this information against the rules defined in `policyConfiguration.yml`, and returns a final `allow` or `deny` verdict.

4.  **Keycloak (Docker Container):** The authoritative source for identity. It manages user authentication, user roles, and secure token issuance (OIDC).

5.  **P2P Network (`Networking.py`):** A custom networking layer that enables the independent components to communicate directly with each other without a central broker, passing requests and decisions between nodes.

   ![image](https://github.com/user-attachments/assets/09120f91-c20e-4b0a-be6c-978ac89746db)



### Standard Access Request Flow

1.  A user logs in via the **Web UI**, authenticating against **Keycloak**.
2.  The user selects a protected resource to access.
3.  The **Web UI** node sends the access request to the **Trust Engine** node.
4.  The **Trust Engine** calculates a dynamic trust score by evaluating the user's identity, device context, historical behavior, and an ML-based anomaly score.
5.  The **Trust Engine** sends the user's details and the calculated trust score to the **Policy Engine**.
6.  The **Policy Engine** loads the rules from `policyConfiguration.yml` and compares the user's trust score and role against the required thresholds for the requested resource.
7.  The **Policy Engine** returns an `allow` or `deny` decision to the **Web UI**.
8.  The **Web UI** grants or denies access to the resource.

---

## Technology Stack

-   **Backend:** Python, Flask
-   **Authentication:** Keycloak, OpenID Connect (OIDC)
-   **Machine Learning:** Scikit-learn, Pandas, Joblib (for the Isolation Forest model)
-   **Networking:** `p2pnetwork` library for peer-to-peer communication
-   **Database:** SQLAlchemy with SQLite (for PAM request tracking)
-   **Frontend:** HTML, CSS, JavaScript, Tailwind CSS
-   **Containerization:** Docker, Docker Compose (for Keycloak)

---

## Setup and Installation

### Prerequisites

-   Python 3.9+
-   Docker and Docker Compose
-   Git

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd bentleyoph-zta
```

### 2. Set Up a Python Virtual Environment

```bash
# For Unix/macOS
python3 -m venv venv
source venv/bin/activate

# For Windows
python -m venv venv
.\venv\Scripts\activate
```

### 3. Install Dependencies

Install all the required Python packages from the `requirements.txt` file.

```bash
pip install -r requirements.txt
```

### 4. Launch Keycloak

Navigate to the `Keycloak` directory and start the Keycloak and PostgreSQL containers using Docker Compose.

```bash
cd Keycloak
docker-compose up -d
```

**Important:** You will need to manually configure Keycloak after it starts:
-   Log in to the admin console at `http://localhost:8080` (user: `admin`, pass: `admin`).
-   Create a new realm named `myrealm`.
-   Create a new client named `ZeroTrustPlatform` and configure it according to `ZeroTrustWebUI/client_secrets.json`.
-   Create the necessary roles (e.g., `Branch Manager`, `Security Analyst`) and assign them to users.

### 5. Run the Application Components

Open three separate terminals, activate the virtual environment in each, and run the engines.

**Terminal 1: Run the Web UI**

```bash
cd ZeroTrustWebUI
./runWebUI.sh
# Or: python3 app.py
```

**Terminal 2: Run the Trust Engine**

```bash
./runTrustEngine.sh
# Or: python3 TrustEngine.py
```

**Terminal 3: Run the Policy Engine**

```bash
./runPolicyEngine.sh
# Or: python3 PolicyEngine.py
```

---

## Usage

1.  **Access the Platform:** Open your web browser and navigate to `http://localhost:5000`.
2.  **Authenticate:** Click the "Authenticate" button to be redirected to the Keycloak login page. Log in with a user you created in the `myrealm` realm.
3.  **Explore the Dashboard:**
    -   **Access Resources:** Navigate to the resource selection page to test the dynamic access control flow.
    -   **Configure Policies:** Modify trust score weights and access thresholds in the policy configuration panel.
    -   **Monitor Logs:** View real-time access logs, including trust scores and policy decisions.
    -   **Use PAM:** Request and approve privileged access to experience the JIT workflow.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
