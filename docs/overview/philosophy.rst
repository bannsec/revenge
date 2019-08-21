==========
Philosophy
==========

The philosophy for ``revenge`` is to make all common binary reverse
engineering tasks pythonic. With this in mind, you will find that there are
many classes. Things that might not even appear to be python classes, may be
custom classes behind the scenes. This provides great flexibility in what you
can do in consice commands.

Most classes in ``revenge`` will have a lot of custom overrides. If you're
unsure of what to do with a class, try runing ``__repr__`` or ``print`` on it,
as often times those will produce different and useful results.

It should be noted that, at least for the time being, this application is
focused on dynamic reverse engineering. That means, all commands will return
information about the process `as it is right now`. Addresses will change and
values will change.
