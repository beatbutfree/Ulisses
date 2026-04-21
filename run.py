# run.py
from agent.runner import run_pipeline
import json

alert = {
    "decoder": {"name": "windows_eventchannel"},
    "rule": {"id": "60106", "level": 10, "description": "Windows logon failure"},
    "data": {
        "win": {
            "eventdata": {
                "ipAddress": "192.168.1.50",
                "targetUserName": "jdoe"
            }
        }
    }
}

report = run_pipeline(
    alert=alert,
    soar_prompt="Multiple failed logons reported by helpdesk for this IP."
)

print(json.dumps(report, indent=2))
