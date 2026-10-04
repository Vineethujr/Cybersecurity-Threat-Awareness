"""Flask application factory. Run from the project root:  python -m backend.app"""
from flask import Flask, jsonify, request, send_from_directory
from .config import Config
from .db import close_db, init_db
from .routes.api import bp
from .utils.rate_limit import RateLimiter


def create_app(overrides: dict | None = None) -> Flask:
    cfg = {k: getattr(Config, k) for k in dir(Config) if k.isupper()}
    cfg.update(overrides or {})
    app = Flask(__name__, static_folder=cfg["FRONTEND_DIR"], static_url_path="")
    app.config.update(cfg)
    init_db(app.config)
    limiter = RateLimiter(app.config["RATE_LIMIT_PER_MIN"])

    @app.before_request
    def _limit():
        if request.path.startswith("/api") and not limiter.allow(request.remote_addr or "?"):
            return jsonify({"error": "Rate limit exceeded. Try again shortly."}), 429

    @app.after_request
    def _headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
                                                   "style-src 'self' 'unsafe-inline'; img-src 'self' data:")
        return resp

    @app.errorhandler(404)
    def _404(_e):
        return (jsonify({"error": "Not found."}), 404) if request.path.startswith("/api") else ("Not found", 404)

    @app.errorhandler(405)
    def _405(_e):
        return jsonify({"error": "Method not allowed."}), 405

    @app.errorhandler(500)
    def _500(_e):
        return jsonify({"error": "Internal server error."}), 500   # never leak stack traces

    app.teardown_appcontext(close_db)
    app.register_blueprint(bp)

    @app.get("/")
    def index():
        return send_from_directory(app.static_folder, "index.html")

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
