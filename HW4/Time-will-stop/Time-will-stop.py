#!/usr/bin/env python3

import subprocess, re

txt = subprocess.check_output('strings time_will_stop',shell=True)
matchObj = re.search( r'(FLAG{.*})', txt.decode('utf-8'), re.I)
print(matchObj.group(1))