#!/usr/bin/env python3
# dashboard.py — Advanced real-time web dashboard for the Healthcare IPS
# Run alongside agent.py in a separate terminal on IPS-Node
# Access from Windows browser at: http://192.168.56.101:5000

from flask import Flask, jsonify
import json, os

RESULTS_DIR = "/home/student/ips_project/results/"
STATE_FILE  = RESULTS_DIR + "live_state.json"
HTML_FILE   = "/home/student/ips_project/agent/dashboard.html"

app = Flask(__name__)

@app.route('/')
def index():
    with open(HTML_FILE, 'r') as f:
        return f.read()

@app.route('/api/state')
def state():
    try:
        if not os.path.exists(STATE_FILE):
            return jsonify({'error': 'Agent not running yet — start agent.py first'})
        with open(STATE_FILE) as f:
            return jsonify(json.load(f))
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    print("\n" + "="*55)
    print("  Healthcare IPS — Security Operations Dashboard")
    print("="*55)
    print(f"\n  Open in your Windows browser:")
    print(f"  --> http://192.168.56.101:5000")
    print(f"\n  Make sure agent.py is also running in another terminal.")
    print(f"  Dashboard auto-refreshes every 3 seconds.\n")
    app.run(host='0.0.0.0', port=5000, debug=False) 
