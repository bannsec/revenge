Welcome to revenge's documentation!
===================================
REVerse ENGineering Environment (``revenge``) was created as a python centric
environment for many things reversing related. The idea is to create a
cross-platform API to interact with binaries in different ways, simplify
reverse engineering, and ultimately achieve a goal faster.

For the time being, ``revenge`` heavily relies on ``frida``. On the plus side,
``frida`` is a nice cross platform DBI (which is why it was the building
block). It also means that any bugs in ``frida`` will likely affect ``revenge``
as well.

If you have suggestions for what you would like to see ``revenge`` do, submit
an issue ticket to my `github <https://github.com/bannsec/revenge>`_.

.. toctree::
    :maxdepth: 1
    :caption: Overview
    :hidden:

    overview/installation
    overview/quickstart
    overview/philosophy
    overview/native/index
    overview/release_notes
    overview/techniques
    overview/writeups

.. toctree::
    :maxdepth: 1
    :caption: API
    :hidden:

    api/native/index
    api/java/index
    api/techniques/index

.. toctree::
    :maxdepth: 1
    :caption: Platforms
    :hidden:

    platform/android/index
    platform/java/index
    platform/linux/index
    platform/macos/index
    platform/windows/index

