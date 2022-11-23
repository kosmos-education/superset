from flask import Flask, render_template, jsonify
import requests
import json
import os

app = Flask(__name__)

@app.route('/')
def hello():
	return render_template('index.html')
