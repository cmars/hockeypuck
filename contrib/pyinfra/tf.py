import json
import os
from subprocess import check_output

os.chdir(os.path.dirname('./' + __file__))
output_json = check_output(['terraform', 'output', '-json']).decode().strip()
output = json.loads(output_json)

tf_nodes = [(ip, {'ssh_user': 'ubuntu', 'peers': [other for other in output['hkp_public_ips']['value'] if other != ip]})
            for ip in output['hkp_public_ips']['value']]
