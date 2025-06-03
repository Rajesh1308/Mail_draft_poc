import os
import json
import base64
from flask import Flask, request, redirect, jsonify, session
from email.message import EmailMessage
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from flask_session import Session
from waitress import serve

app = Flask(__name__)
app.secret_key = 'your-very-secret-key'  # Replace in production

# Use filesystem sessions (or use Redis/DB in production)
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

credentials_dict = json.loads(os.environ.get("GOOGLE_CREDENTIALS_JSON"))

# === CONFIG ===
CLIENT_SECRETS_FILE = 'credentials.json'
SCOPES = ['https://www.googleapis.com/auth/gmail.compose']
REDIRECT_URI = 'https://mail-draft-poc.onrender.com/auth/callback'

with open("credentials.json", "w") as f:
    json.dump(credentials_dict, f)

# === ROUTES ===

@app.route('/')
def home():
    return '<a href="/authorize">Login with Google</a>'

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(
        "credentials.json",
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true')
    session['state'] = state
    return redirect(auth_url)

@app.route('/auth/callback')
def oauth2_callback():
    state = session.get('state')

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
        state=state
    )
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    # Save credentials to session
    session['credentials'] = creds.to_json()
    return 'Authentication successful! <a href="/create-draft-form">Create Draft</a>'

@app.route('/create-draft-form')
def create_draft_form():
    return '''
        <form method="POST" action="/create-draft">
            <input name="to" placeholder="To" /><br/>
            <input name="subject" placeholder="Subject" /><br/>
            <textarea name="body" placeholder="Body"></textarea><br/>
            <button type="submit">Create Draft</button>
        </form>
    '''

@app.route('/create-draft', methods=['POST'])
def create_draft():
    if 'credentials' not in session:
        return redirect('/authorize')

    creds = Credentials.from_authorized_user_info(json.loads(session['credentials']), SCOPES)

    # Handle form or JSON input
    if request.is_json:
        data = request.get_json()
    else:
        data = request.form

    to = data.get("to")
    subject = data.get("subject")
    body = data.get("body")

    if not to or not subject or not body:
        return jsonify({"error": "Missing 'to', 'subject', or 'body'"}), 400

    try:
        service = build('gmail', 'v1', credentials=creds)

        message = EmailMessage()
        message.set_content(body)
        message['To'] = to
        message['Subject'] = subject
        message['From'] = "me"

        encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        create_message = {'message': {'raw': encoded_message}}

        draft = service.users().drafts().create(userId="me", body=create_message).execute()

        return jsonify({"draft_id": draft['id'], "status": "Draft created successfully."})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=5000)
