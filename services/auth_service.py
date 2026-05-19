from flask import Flask, request, jsonify

app = Flask(__name__)

USERS = {
    "employee1":{
        "password": "pass123",
        "ip": "10.0.1.11",
        "role": "employee"
    },
    "employee2":{
        "password": "pass123",
        "ip": "10.0.1.12",
        "role": "employee"
    },
    "employee3":{
        "password": "pass123",
        "ip": "10.0.1.13",
        "role": "employee"
    },
    "admin":{
        "password": "pass123",
        "ip": "10.0.2.11",
        "role": "admin"
    },
    "guest":{
        "password": "pass123",
        "ip": "10.0.4.11",
        "role": "guest"
    }
}

authenticated_hosts = {
    "10.0.3.11": {
        "username": "appserv",
        "role": "app"
    },
    "10.0.3.12": {
        "username": "dbserv",
        "role": "db"
    }
}

attributes = {
    "10.0.1.11": {
        "device_trusted": True,
        "mfa": True,
        "risk": "low"
    },
    "10.0.1.12": {
        "device_trusted": False,
        "mfa": False,
        "risk": "medium"
    },
    "10.0.1.13": {
        "device_trusted": True,
        "mfa": False,
        "risk": "medium"
    },
    "10.0.2.11": {
        "device_trusted": True,
        "mfa": True,
        "risk": "low"
    },
    "10.0.3.11": {
        "device_trusted": True,
        "mfa": True,
        "risk": "low"
    },
    "10.0.3.12": {
        "device_trusted": True,
        "mfa": True,
        "risk": "low"
    }
}

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    user = USERS.get(username)

    if not user or user["password"] != password:
        return jsonify({"authenticated": False}), 401

    authenticated_hosts[user["ip"]] = {
        "username": username,
        "role": user["role"]
    }

    return jsonify({
        "authenticated": True,
        "ip": user["ip"],
        "role": user["role"]
    })

@app.route("/authenticated", methods=["GET"])
def authenticated():
    return jsonify(authenticated_hosts)

@app.route("/attributes/<ip>", methods=["GET"])
def get_attributes(ip):
    return jsonify(attributes.get(ip, {}))

@app.route("/attributes/<ip>", methods=["POST"])
def update_attributes(ip):
    data = request.json
    attributes.setdefault(ip, {}).update(data)
    return jsonify(attributes[ip])

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        ssl_context="adhoc"
    )
