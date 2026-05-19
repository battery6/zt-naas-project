from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Simulated DB Service"

if __name__ == "__main__":
    app.run(
        host="10.0.3.12",
        port=5433,
        ssl_context=(
            "/home/philip/zt-naas-project/certs/dbserv.crt",
            "/home/philip/zt-naas-project/certs/dbserv.key"
        )
    )
