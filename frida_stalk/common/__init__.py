import json
import os

here = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(here, 'windows_messages_by_name.json')) as f:
    windows_messages_by_name = json.loads(f.read())

with open(os.path.join(here, 'windows_messages_by_id.json')) as f:
    windows_messages_by_id = json.loads(f.read())
