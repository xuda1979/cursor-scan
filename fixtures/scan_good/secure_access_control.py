"""Fully secured Flask API — every route carries an auth decorator.

The project uses auth throughout, but unlike scan_bad there is no bare
route, so the access-control rule must stay silent here (AC2: 0 findings).
"""

from flask import Flask, render_template
from flask_login import login_required

app = Flask(__name__)


@app.route("/")
@login_required
def index():
    return render_template("index.html", name="guest")


@app.route("/reports")
@login_required
def reports():
    return render_template("reports.html")
