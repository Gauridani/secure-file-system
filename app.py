import os
import uuid

from flask import (
    Flask,
    render_template,
    request,
    send_file
)

from werkzeug.utils import secure_filename

from crypto_utils import (
    encrypt_file,
    decrypt_file
)


app = Flask(__name__)

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/")
def home():

    return render_template("index.html")


@app.route("/encrypt", methods=["POST"])
def encrypt():

    uploaded_file = request.files.get("file")
    password = request.form.get("password")

    if not uploaded_file:
        return "No file selected", 400

    if not password:
        return "Password is required", 400

    original_name = secure_filename(
        uploaded_file.filename
    )

    if not original_name:
        return "Invalid filename", 400

    unique_id = uuid.uuid4().hex

    input_path = os.path.join(
        UPLOAD_FOLDER,
        unique_id + "_" + original_name
    )

    encrypted_name = original_name + ".enc"

    output_path = os.path.join(
        UPLOAD_FOLDER,
        unique_id + "_" + encrypted_name
    )

    uploaded_file.save(input_path)

    try:

        encrypt_file(
            input_path,
            output_path,
            password
        )

    finally:

        if os.path.exists(input_path):
            os.remove(input_path)

    return send_file(
        output_path,
        as_attachment=True,
        download_name=encrypted_name
    )


@app.route("/decrypt", methods=["POST"])
def decrypt():

    uploaded_file = request.files.get("file")
    password = request.form.get("password")

    if not uploaded_file:
        return "No encrypted file selected", 400

    if not password:
        return "Password is required", 400

    original_name = secure_filename(
        uploaded_file.filename
    )

    unique_id = uuid.uuid4().hex

    input_path = os.path.join(
        UPLOAD_FOLDER,
        unique_id + "_" + original_name
    )

    output_name = original_name

    if output_name.endswith(".enc"):
        output_name = output_name[:-4]

    output_path = os.path.join(
        UPLOAD_FOLDER,
        unique_id + "_" + output_name
    )

    uploaded_file.save(input_path)

    try:

        decrypt_file(
            input_path,
            output_path,
            password
        )

    except ValueError as error:

        if os.path.exists(input_path):
            os.remove(input_path)

        return str(error), 400

    finally:

        if os.path.exists(input_path):
            os.remove(input_path)

    return send_file(
        output_path,
        as_attachment=True,
        download_name=output_name
    )


if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )