from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Insecure HTTP App Server"

if __name__ == "__main__":
    app.run(
        host="10.0.3.11",
        port=80
    )
