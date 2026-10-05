# IMPORT LIBRARIES
import win32evtlog
import requests
import json

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
    "model": "qwen3.5",  # Replace with the model name you're using
    "messages": [{"role": "user", "content": f"""You are a Tier 3 SOC Analyst. Analyze the following Windows events. 
                    Respond ONLY with JSON.
                    Schema:
                    {{
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
    for line in response.iter_lines(decode_unicode=True):
        if line:  # Ignore empty lines
            try:
                # Parse each line as a JSON object
                json_data = json.loads(line)
                # Extract and print the assistant's message content
                if "message" in json_data and "content" in json_data["message"]:
                    print(json_data["message"]["content"], end="")
            except json.JSONDecodeError:
                print(f"\nFailed to parse line: {line}")
    print()  # Ensure the final output ends with a newline
else:
    print(f"Error: {response.status_code}")
    print(response.text)