from mitmproxy import http, ctx
from mitmproxy.io import FlowWriter
import copy
import os
import urllib.parse
import json

# Define the directory to save the flow files
flow_dir = "saved_flows"
os.makedirs(flow_dir, exist_ok=True)

# Define the token and parameter to mark altered requests
alteration_indicator = "ex'\"><h1>akira</h1>"
altered_header = "x-altered"

def response(flow: http.HTTPFlow) -> None:
    # Check if the response is HTML
    content_type = flow.response.headers.get("Content-Type", "")
    if "text/html" not in content_type:
        return  # Skip non-HTML responses

    # Check if the request has already been altered
    if altered_header in flow.request.headers:
        check_altered_reflection(flow)
        return

    # Handle GET and POST requests
    if flow.request.method == "GET":
        process_parameters(flow, flow.request.query)
    elif flow.request.method == "POST":
        process_post_request(flow)

def process_post_request(flow):
    content_type = flow.request.headers.get("Content-Type", "")
    if "application/x-www-form-urlencoded" in content_type:
        params = urllib.parse.parse_qs(flow.request.get_text())
        process_parameters(flow, params)
    elif "application/json" in content_type:
        try:
            params = json.loads(flow.request.get_text())
            if isinstance(params, dict):
                process_parameters(flow, params)
        except json.JSONDecodeError:
            ctx.log.info("JSON decode error")

def process_parameters(flow, params):
    for param, value in params.items():
        if isinstance(value, list):  # Handle lists for form data
            value = value[0]
        if isinstance(value, str) and value in flow.response.text:
            alter_and_replay(flow, param, value)

def alter_and_replay(original_flow, param, original_value):
    altered_value = original_value + alteration_indicator
    altered_flow = alter_request(original_flow, param, altered_value)
    if altered_flow:
        ctx.master.commands.call("replay.client", [altered_flow])

def alter_request(original_flow, param, altered_value):
    new_request = copy.deepcopy(original_flow.request)

    if original_flow.request.method == "GET":
        new_request.query[param] = altered_value
    else:
        content_type = new_request.headers.get("Content-Type", "")
        if "application/x-www-form-urlencoded" in content_type:
            params = urllib.parse.parse_qs(new_request.get_text())
            params[param] = [altered_value]
            new_request.text = urllib.parse.urlencode(params, doseq=True)
        elif "application/json" in content_type:
            try:
                body = json.loads(new_request.get_text())
                if param in body and isinstance(body[param], str):
                    body[param] = altered_value
                    new_request.text = json.dumps(body)
            except json.JSONDecodeError:
                pass

    # Mark the request as altered
    new_request.headers[altered_header] = "true"

    altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
    altered_flow.request = new_request
    return altered_flow

def check_altered_reflection(flow):
    if alteration_indicator in flow.response.text:
        ctx.log.info(f"Altered parameter reflected in the response: {flow.request.url}")
        save_flow(flow)  # Save the altered flow

def save_flow(flow):
    identifier = f"{flow.request.method}_{flow.request.host}_{flow.request.path}".replace("/", "_")
    filename = os.path.join(flow_dir, f"{identifier}.mitm")
    try:
        with open(filename, "wb") as file:
            fw = FlowWriter(file)
            fw.add(flow)
        ctx.log.info(f"Saved altered flow to {filename}")
    except OSError as e:
        ctx.log.error(f"Error saving .mitm file: {e}")

addons = [response]
