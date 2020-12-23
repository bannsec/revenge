
import requests
import zipfile
import re
import io
import os
import subprocess
import shutil


def install_radare():
    r = requests.get("https://github.com/radareorg/radare2/releases/latest")
    download_url = "https://github.com/" + re.findall(r"href=\"(.*?archive/release.*?\.zip)", r.text)[0]
    r = requests.get(download_url)

    zfile = zipfile.ZipFile(io.BytesIO(r.content))

    install_dir = r"C:\radare2"
    os.makedirs(install_dir)

    zfile.extractall(install_dir)

    # Copy all files up one
    subdir = os.listdir(install_dir)[0]
    subdir = os.path.join(install_dir, subdir)

    for f in os.listdir(subdir):
        shutil.move(os.path.join(subdir, f), install_dir)

install_radare()
