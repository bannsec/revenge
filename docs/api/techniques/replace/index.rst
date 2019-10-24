Replace Techniques
==================

.. toctree::
    :maxdepth: 1

About
-----

Replace techniques take advantage of rewriting parts of the binary prior to it
being executed.

Pros:

- Can have as many of these running as needed (so long as they don't overlap)
- Generally more performant and reliable than stalking

Cons:

- Cannot as easily follow unexpected code paths
- Less granular in some cases
