
import appdirs

def init():
    global app_dirs

    app_dirs = appdirs.AppDirs(appname='frida-util', appauthor='bannsec')

try:
    app_dirs
except NameError:
    init()
