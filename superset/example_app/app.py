from flask import Flask, render_template, jsonify
import requests
import json
import os

app = Flask(__name__)

@app.route('/')
def hello():
	return render_template('index.html')

@app.route("/guest-token", methods=["GET"])
# @login_required
def guest_token():
	## 1. Authenticate with Preset API
	url = "https://manage.app.preset.io/api/v1/auth/"
	payload = json.dumps({
		"name": "test",
		"secret": "test"
	})

	headers = {
		'Content-Type': 'application/json',
		'Accept': 'application/json'
	}

	response1 = requests.request("POST", url, headers=headers, data=payload)
	preset_access_token = json.loads(response1.text)['payload']['access_token']

	## 2. Fetch Guest Token for Embedded Dashboard
	payload = json.dumps({
		"user": {
			"username": "bonjour",
			"first_name": "bon",
			"last_name": "jour"
		},
		"resources": [{
			"type": "dashboard",
			"id": "8e85aeee-da7c-4cb6-b480-8190f3b6efb3"
		}],
		"rls": []
	})

	bearer_token = "Bearer " + preset_access_token
	response2 = requests.post(
		"http://localhost:8088/api/v1/teams/<TEAM_ID>/workspaces/<WORKSPACE_ID>/guest-token/",
		data=payload,
		headers={ "Authorization": bearer_token, 'Accept': 'application/json', 'Content-Type': 'application/json' })
	# Return guest_token as valid JSON to frontend
	return jsonify(response2.json()['payload']['token'])
