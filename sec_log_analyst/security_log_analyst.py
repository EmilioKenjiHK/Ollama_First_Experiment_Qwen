# IMPORT LIBRARIES
import win32evtlog
import json
import ollama



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

# Initialize the Ollama client
client = ollama.Client()

# Define the model and the input prompt
model = "gemma4:e2b"  # Replace with your model name
prompt = f"""You are a Tier 3 SOC Analyst. Analyze the following Windows events. Respond with a separate JSON for each Windows Event.
            Schema:
            {{
            "EventID":"",
            "TimeGenerated":"",
            "threat_assessment":"",
            "severity":"",
            "mitre_technique":"",
            "recommended_actions":[]
            }}
            Events: {test_events}"""

# Send the query to the model
response = client.generate(model=model, prompt=prompt)

# Print the response from the model
print("Response from Ollama:")
print(response.response)

client.close()
