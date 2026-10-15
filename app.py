from flask import Flask, jsonify, request
from analyzer import analyze

app = Flask(__name__, static_folder="static", static_url_path="")


@app.get("/")
def index():
    return app.send_static_file("index.html")


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}
    content = data.get("content", "")
    if not isinstance(content, str) or not content.strip():
        return jsonify(error="No QR content provided."), 400
    if len(content) > 4096:
        return jsonify(error="QR content is too long."), 413
    return jsonify(analyze(content))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
