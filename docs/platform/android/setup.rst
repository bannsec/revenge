=====
Setup
=====

Initially setting up ``revenge`` to work with an android emulator involves
using the device_types. For this doc, I'll assume that you already have an
android running, in either emulator or physical form.

.. note::

    You must have root access to the device on which you wish to run
    ``revenge``.

Base Connection
===============

Base interactions for ``revenge`` will go through the device object.
Instantiating this object will attempt to automatically install, run and
connect to the latest version of frida server for your android.

Examples
--------

.. code-block:: python3

    from revenge import device_types

    # Connect to the first usb device adb finds
    android = device_types.AndroidDevice(type="usb")
    "<AndroidDevice emulator-5554>"

    # Connect to device with the given id
    android = device_types.AndroidDevice(id="emulator-5554")
    "<AndroidDevice emulator-5554>"

Installing/Removing APKs
========================

A convenience method exists to install and uninstall apks directly from
``revenge``.

Examples
--------

.. code-block:: python3

    android.install("something.apk")
    android.uninstall("com.blerg.something")
    android.uninstall(android.applications['*something*'])

Shell
=====

You can drop into an interactive shell.

Examples
--------

.. code-block:: python3

    android.shell()

List Processes/Applications
===========================

You can list both running processes and running applications. Applications have
their own class.

:class:`revenge.device_types.android.applications.AndroidApplications`

Examples
--------

.. code-block:: python3

    android.device.enumerate_processes()
    """
    <clip>
     Process(pid=1502, name="tombstoned"),
     Process(pid=1503, name="android.hardware.biometrics.fingerprint@2.1-service"),
     Process(pid=1506, name="iptables-restore"),
     Process(pid=1507, name="ip6tables-restore"),
     Process(pid=1604, name="dhcpclient"),
     Process(pid=1607, name="sh"),
     Process(pid=1608, name="sleep"),
     Process(pid=1619, name="ipv6proxy"),
     Process(pid=1622, name="hostapd"),
     Process(pid=1624, name="dhcpserver"),
     Process(pid=1633, name="system_server"),
     Process(pid=1740, name="com.android.inputmethod.latin"),
     Process(pid=1748, name="com.android.systemui"),
     Process(pid=1790, name="webview_zygote32"),
     Process(pid=1846, name="wpa_supplicant"),
     Process(pid=1851, name="com.android.phone"),
    <clip>
    """

    # List applications
    list(android.applications)
    """
    <clip>
     Application(identifier="com.android.dialer", name="Phone", pid=2084),
     Application(identifier="com.android.gallery3d", name="Gallery"),
     Application(identifier="com.android.emulator.smoketests", name="Emulator Smoke Tests"),
     Application(identifier="android.ext.services", name="Android Services Library", pid=2566),
     Application(identifier="com.android.packageinstaller", name="Package installer"),
     Application(identifier="com.svox.pico", name="Pico TTS"),
     Application(identifier="com.android.proxyhandler", name="ProxyHandler"),
     Application(identifier="com.android.inputmethod.latin", name="Android Keyboard (AOSP)", pid=1740),
     Application(identifier="org.chromium.webview_shell", name="WebView Shell"),
     Application(identifier="com.android.managedprovisioning", name="Work profile setup"),
    <clip>
    """

Running Applications
====================

You can spawn and attach to applications via command-line.

Examples
--------

.. code-block:: python3

    # Launch application and retrieve corresponding revenge.Process instance
    p = android.spawn("com.android.email", gated=False, load_symbols="*dex")
    <Process <pre-initialized>:4335>

    calc = android.applications['*calc*']
    p = android.spawn(calc, gated=False, load_symbols="*dex")

    # If the app is already running, you can just attach
    p = android.attach("*calc*", load_symbols="*dex")
