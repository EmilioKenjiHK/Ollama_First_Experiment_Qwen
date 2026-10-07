# IMPORT LIBRARIES
import win32evtlog
import requests
import json
import re
from datetime import datetime
import pandas as pd
import plotly.graph_objs as go
from plotly.subplots import make_subplots


server = 'localhost'
log_type = 'Security'
# Set up the base URL for the local Ollama API
url = "http://localhost:11434/api/chat"


# Requires admin access -> Execute from local PS
hand = win32evtlog.OpenEventLog(server, log_type)


# Reading events from live Windows Security Event Log via Windows Event Log API
events = win32evtlog.ReadEventLog(
    hand,
    win32evtlog.EVENTLOG_BACKWARDS_READ |
    win32evtlog.EVENTLOG_SEQUENTIAL_READ,
    0
)


# Step 1: Extract Windows Security Event Logs
# Testing purposes: Only the first 3 Event logs
test_events = []
for event in events[:3]:
    event_data = {
    "event_id": event.EventID,
    "time_generated": str(event.TimeGenerated),
    #"source_name": event.SourceName,
    #"computer_name": event.ComputerName,
    #"details": event.StringInserts
    }
    test_events.append(event_data)


# Define the payload (your input prompt)
payload = {
    "model": "gemma4:e2b",  # Replace with the model name you're using
    "messages": [{"role": "user", "content": f"""You are a Tier 3 SOC Analyst. Analyze the following Windows events. 
                    Respond with a separate JSON for each Windows Event.
                    Schema:
                    {{
                    "EventID":"",
                    "TimeGenerated":"",
                    "threat_assessment":"",
                    "severity":"",
                    "mitre_technique":"",
                    "recommended_actions":[]
                    }}
                    Events: {test_events}"""}]
}


# Send the HTTP POST request with streaming enabled
response = requests.post(url, json=payload, stream=True)

# Check the response status
if response.status_code == 200:
    print("Streaming response from Ollama:")
    accumulated_content = ""
    for line in response.iter_lines(decode_unicode=True):
        if line:  # Ignore empty lines
            try:
                # Parse each line as a JSON object
                json_data = json.loads(line)
                # Extract and accumulate the assistant's message content
                if "message" in json_data and "content" in json_data["message"]:
                    content = json_data["message"]["content"]
                    accumulated_content += content

            except json.JSONDecodeError:
                print(f"\nFailed to parse line: {line}")

    response_text = accumulated_content
    

    print(f"Saving this onto the JSON file: {response_text}") # Checking that we receive the expected output

    # Write the list of results to the file
    log_file_path = "security_log_dashboard.json"
    with open(log_file_path, 'w') as json_file:
        json.dump(response_text, json_file)

    print(f"JSON data has been written to {log_file_path}")

else:
    print(f"Error: {response.status_code}")