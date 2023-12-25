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
altered_token = "_altered123"
altered_header = "x-altered-flow"  # Lowercase to comply with HTTP/2

def response(flow: http.HTTPFlow) -> None:
    # Check if the response is HTML
    content_type = flow.response.headers.get("Content-Type", "")
    if "text/html" not in content_type:
        return  # Skip non-HTML responses

    # Check if the request has already been altered
    if altered_header in flow.request.headers:
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
        # Ensure that the value is a string before checking for reflections
        if isinstance(value, str) and value in flow.response.text:
            altered_flow = alter_request(flow, param, value)
            if altered_flow:
                ctx.master.commands.call("replay.client", [altered_flow])
                save_flow(altered_flow)  # Save the altered flow

def alter_request(original_flow, param, original_value):
    new_request = copy.deepcopy(original_flow.request)
    altered_value = original_value + altered_token

    if original_flow.request.method == "GET":
        new_request.query[param] = altered_value
    else:
        if "application/x-www-form-urlencoded" in new_request.headers.get("Content-Type", ""):
            params = urllib.parse.parse_qs(new_request.get_text())
            params[param] = [altered_value]
            new_request.text = urllib.parse.urlencode(params, doseq=True)
        elif "application/json" in new_request.headers.get("Content-Type", ""):
            try:
                body = json.loads(new_request.get_text())
                if param in body and isinstance(body[param], str):
                    body[param] = altered_value
                    new_request.text = json.dumps(body)
            except json.JSONDecodeError:
                pass

    # Mark the request as altered
    new_request.headers[altered_header] = altered_token

    altered_flow = http.HTTPFlow(original_flow.client_conn, original_flow.server_conn)
    altered_flow.request = new_request
    return altered_flow

def save_flow(flow):
    # Generate a unique identifier for each flow based on its details
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
