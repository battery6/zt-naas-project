HOSTS = {
    "10.0.1.11": {
        "segment": "user",
        "role": "user",
        "name": "h1user",
    },
    "10.0.1.12": {
        "segment": "user",
        "role": "user",
        "name": "h2user",
    },
    "10.0.1.13": {
        "segment": "user",
        "role": "user",
        "name": "h3user",
    },
    "10.0.2.11": {
        "segment": "admin",
        "role": "admin",
        "name": "h4admin",
    },
    "10.0.3.11": {
        "segment": "appserver",
        "role": "app",
        "name": "h5appserv",
        "resource_sensitivity": "medium",
    },
    "10.0.3.12": {
        "segment": "dbserver",
        "role": "db",
        "name": "h6dbserv",
        "resource_sensitivity": "high",
    },
    "10.0.4.11": {
        "segment": "guest",
        "role": "guest",
        "name": "h7guest",
        "never_trusted": True,
    },
}
