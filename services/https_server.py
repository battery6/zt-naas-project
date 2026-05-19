from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Secure App Server"

if __name__ == "__main__":
    app.run(
        host="10.0.3.11",
        port=443,
        ssl_context=(
            "/home/philip/zt-naas-project/certs/appserv.crt",
            "/home/philip/zt-naas-project/certs/appserv.key"
        )
    )
