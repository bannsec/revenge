import json
import os

here = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(here, 'windows_messages_by_name.json')) as f:
    windows_messages_by_name = json.loads(f.read())

with open(os.path.join(here, 'windows_messages_by_id.json')) as f:
    windows_messages_by_id = json.loads(f.read())
    # JSON doesn't support int keys
    windows_messages_by_id = {int(x):y for x,y in windows_messages_by_id.items()}

with open(os.path.join(here, 'windows_keys_by_id.json')) as f:
    windows_keys_by_id = json.loads(f.read())
    # JSON doesn't support int keys
    windows_keys_by_id = {int(x):y for x,y in windows_keys_by_id.items()}
