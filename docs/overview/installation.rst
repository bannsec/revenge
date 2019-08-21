############
Installation
############

There are two primary ways to install and run ``revenge``. You can use python
directly, or you can utilize the ``docker`` image.

.. note::

    Python 2 is NOT supported!

Python3
=======

Virtual Environment
-------------------

It's recomended to install ``revenge`` into a python virtual environment. If
you haven't used this before, don't worry, it's easy.

First, install the python virtualenv package::

    $ sudo apt update && sudo apt install -y virtualenv

Next, create a virtual environment for ``revenge``::

    $ virtualenv --python=$(which python3) /opt/revenge

Finally, you need to have it activated when you install or run ``revenge``. Do
this by sourcing the activate script. Note, this may vary depending on what
shell you're using, but the base script should be fine for most.::

    $ source /opt/revenge/bin/activate

Option 1 -- pypi
----------------

The fastest way to get started is to simply pip install revenge.::

    $ pip3 install revenge

Option 2 -- git
---------------

You can install the very latest version of ``revenge`` directly from git::

    $ pip3 install https://github.com/bannsec/revenge/archive/master.zip

Docker
======

You can use the auto-building docker image with the following::

    $ sudo docker run -it --rm --privileged bannsec/revenge
