INVESTIGATION_GRAPHS = {

    "BRUTE_FORCE": {
        "Alert": [
            "IP Reputation",
            "User History",
            "Login Pattern"
        ],

        "IP Reputation": [
            "Known Malicious IP",
            "IP Geographic Anomaly"
        ],

        "User History": [
            "Previous Failed Logins",
            "MFA Status"
        ],

        "Login Pattern": [
            "Login Frequency",
            "Login Time Anomaly"
        ],

        "Known Malicious IP": [
            "Threat Confirmed"
        ],

        "IP Geographic Anomaly": [
            "Threat Confirmed"
        ],

        "Previous Failed Logins": [
            "Threat Confirmed"
        ],

        "MFA Status": [
            "Threat Confirmed"
        ],

        "Login Frequency": [
            "Threat Confirmed"
        ],

        "Login Time Anomaly": [
            "Threat Confirmed"
        ],

        "Threat Confirmed": []
    },

    "MALWARE_DETECTION": {
        "Alert": [
            "File Reputation",
            "Process Tree",
            "Endpoint History"
        ],

        "File Reputation": [
            "Known Malicious Hash",
            "Unknown File Hash"
        ],

        "Process Tree": [
            "Suspicious Parent Process",
            "Normal Parent Process"
        ],

        "Endpoint History": [
            "Previous Malware Alerts",
            "Clean History"
        ],

        "Known Malicious Hash": [
            "Threat Confirmed"
        ],

        "Suspicious Parent Process": [
            "Threat Confirmed"
        ],

        "Previous Malware Alerts": [
            "Threat Confirmed"
        ],

        "Unknown File Hash": [
            "Deep File Analysis"
        ],

        "Deep File Analysis": [
            "Threat Confirmed"
        ],

        "Normal Parent Process": [
            "Deep File Analysis"
        ],

        "Clean History": [
            "Deep File Analysis"
        ],

        "Threat Confirmed": []
    },

    "UNAUTHORIZED_USB": {
        "Alert": [
            "Device Policy",
            "User History",
            "File Access"
        ],

        "Device Policy": [
            "Unauthorized Device"
        ],

        "User History": [
            "Previous USB Events"
        ],

        "File Access": [
            "Sensitive File Access"
        ],

        "Unauthorized Device": [
            "Threat Confirmed"
        ],

        "Previous USB Events": [
            "Threat Confirmed"
        ],

        "Sensitive File Access": [
            "Threat Confirmed"
        ],

        "Threat Confirmed": []
    },

    "SUSPICIOUS_PROCESS": {
        "Alert": [
            "Process Reputation",
            "Parent Process",
            "Command Analysis"
        ],

        "Process Reputation": [
            "Known Malicious Process",
            "Unknown Process"
        ],

        "Parent Process": [
            "Suspicious Parent Process",
            "Normal Parent Process"
        ],

        "Command Analysis": [
            "Encoded Command",
            "Normal Command"
        ],

        "Known Malicious Process": [
            "Threat Confirmed"
        ],

        "Suspicious Parent Process": [
            "Threat Confirmed"
        ],

        "Encoded Command": [
            "Threat Confirmed"
        ],

        "Unknown Process": [
            "Deep Process Analysis"
        ],

        "Deep Process Analysis": [
            "Threat Confirmed"
        ],

        "Normal Parent Process": [
            "Deep Process Analysis"
        ],

        "Normal Command": [
            "Deep Process Analysis"
        ],

        "Threat Confirmed": []
    },

    "NETWORK_ANOMALY": {
        "Alert": [
            "Traffic Volume",
            "Destination Reputation",
            "Network History"
        ],

        "Traffic Volume": [
            "Abnormal Volume"
        ],

        "Destination Reputation": [
            "Suspicious Destination",
            "Known Safe Destination"
        ],

        "Network History": [
            "Previous Traffic Pattern"
        ],

        "Abnormal Volume": [
            "Threat Confirmed"
        ],

        "Suspicious Destination": [
            "Threat Confirmed"
        ],

        "Previous Traffic Pattern": [
            "Threat Confirmed"
        ],

        "Known Safe Destination": [
            "Deep Traffic Analysis"
        ],

        "Deep Traffic Analysis": [
            "Threat Confirmed"
        ],

        "Threat Confirmed": []
    },

    "IMPOSSIBLE_TRAVEL": {
        "Alert": [
            "Geolocation Check",
            "Login History",
            "Device History"
        ],

        "Geolocation Check": [
            "Impossible Distance"
        ],

        "Login History": [
            "Recent Login",
            "Normal Login Pattern"
        ],

        "Device History": [
            "Known Device",
            "Unknown Device"
        ],

        "Impossible Distance": [
            "Threat Confirmed"
        ],

        "Recent Login": [
            "Threat Confirmed"
        ],

        "Unknown Device": [
            "Threat Confirmed"
        ],

        "Normal Login Pattern": [
            "Deep Identity Analysis"
        ],

        "Known Device": [
            "Deep Identity Analysis"
        ],

        "Deep Identity Analysis": [
            "Threat Confirmed"
        ],

        "Threat Confirmed": []
    }
}