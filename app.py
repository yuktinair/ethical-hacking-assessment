
from flask import Flask, render_template, request
from pathlib import Path
from werkzeug.utils import secure_filename
from log_analyzer import analyze_logs
import tempfile
import os

app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_LOG = BASE_DIR / "sample_security.log"
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

@app.route("/", methods=["GET", "POST"])
def dashboard():
    result = None
    error = None

    if request.method == "POST":
        uploaded_file = request.files.get("logfile")

        if not uploaded_file or not uploaded_file.filename:
            error = "Please select a log file."
        elif Path(uploaded_file.filename).suffix.lower() != ".log":
            error = "Please upload a .log file."
        else:
            content = uploaded_file.stream.read(MAX_FILE_SIZE + 1)

            if len(content) > MAX_FILE_SIZE:
                error = "File is too large. Maximum size is 1 MB."
            else:
                try:
                    with tempfile.NamedTemporaryFile(
                        mode="wb", suffix=".log", delete=False
                    ) as temp_file:
                        temp_file.write(content)
                        temp_path = temp_file.name

                    try:
                        result = analyze_logs(temp_path)
                    finally:
                        os.remove(temp_path)

                except (OSError, UnicodeError) as exc:
                    error = f"Could not read the log file: {exc}"

    else:
        try:
            result = analyze_logs(SAMPLE_LOG)
        except (OSError, ValueError) as exc:
            error = f"Could not analyze the sample log: {exc}"

    return render_template(
        "dashboard.html",
        result=result,
        error=error
    )

if __name__ == "__main__":
    app.run(debug=True)