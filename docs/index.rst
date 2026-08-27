.. meta::
   :description: Discover the content cache charm, a Juju operator that deploys and manages NGINX.

.. vale Canonical.007-Headings-sentence-case = NO

.. _index:

Content cache operators
========================

.. vale Canonical.007-Headings-sentence-case = YES

A `Juju <https://juju.is/>`_ `charm <https://documentation.ubuntu.com/juju/3.6/reference/charm/>`_
deploying and managing a static web content cache with NGINX on VMs. 

This machine charm manages a NGINX instance configured as a content cache. The configuration for the locations of cache is managed with the `Content Cache Backends Config subordinate charm <https://charmhub.io/content-cache-backends-config>`_. Each Content Cache Backends Config charm stores the configuration for a location and the associated set of backends.

This charm should be used for caching static web content. When a client makes a request, this charm checks if the requested content is cached and valid. For an invalid cache, this charm will query the backends hosts for the content to refresh the cache. This process works well for static content that does not change based on the client. For this type of content, the cache can greatly reduce the load on the backend hosts.

Like any Juju charm, this charm supports one-line deployment, configuration, integration,
scaling, and more. 
For content cache charm, this includes:

- Support for multiple backends via the Content Cache Backends Config subordinate charm.
- Support for HTTPS.
- Observability with COS.

The charm simplifies the operation of an NGINX server as a static web content cache. This makes the charm suitable for users looking for a low maintenance way to reduce load on static websites.

In this documentation
---------------------

.. list-table::
    :header-rows: 0

    * - **Operations**
      - :ref:`Enable COS <how_to_enable_cos>` | :ref:`Upgrade <how_to_upgrade>`
    * - **Design**
      - :ref:`Caching behavior <explanation_caching_behavior>` | :ref:`Charm design <explanation_charm_design>` | :ref:`Components <reference_components>`
    * - **Security**
      - :ref:`Overview <explanation_security>` | :ref:`Connect to HTTPS backends <how_to_enable_https>`

How this documentation is organized
------------------------------------

This documentation uses the `Diátaxis documentation structure <https://diataxis.fr/>`_.

- The :ref:`Tutorial <tutorial_index>` takes you step-by-step through a basic deployment of the content cache charm.
- :ref:`How-to guides <how_to_index>` assume you have basic familiarity with the content cache charm. Learn more about setting up, using, maintaining, and contributing to this charm.
- :ref:`Reference <reference_index>` provides a guide to actions, configurations, relations, and other technical details.
- :ref:`Explanation <explanation_index>` includes topic overviews, background and context and detailed discussion.

Contributing to this documentation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Documentation is an important part of this project, and we take the same open-source approach
to the documentation as the code. As such, we welcome community contributions, suggestions, and
constructive feedback on our documentation.
See :ref:`How to contribute <how_to_contribute>` for more information.

If there's a particular area of documentation that you'd like to see that's missing, please 
`file a bug <https://github.com/canonical/content-cache-operator/issues>`_.

Project and community
---------------------

The content cache charm is a member of the Ubuntu family. It's an open-source project that warmly welcomes community 
projects, contributions, suggestions, fixes, and constructive feedback.

Governance and policies
^^^^^^^^^^^^^^^^^^^^^^^

- `Code of conduct <https://ubuntu.com/community/code-of-conduct>`_

Get involved
^^^^^^^^^^^^

- `Get support <https://discourse.charmhub.io/>`_
- `Join our online chat <https://matrix.to/#/#charmhub-charmdev:ubuntu.com>`_
- :ref:`Contribute <how_to_contribute>`


Thinking about using the content cache charm for your next project?
`Get in touch <https://matrix.to/#/#charmhub-charmdev:ubuntu.com>`_!

.. vale Canonical.013-Spell-out-numbers-below-10 = NO
.. vale Canonical.500-Repeated-words = NO

.. toctree::
    :hidden:
    :maxdepth: 1

    Tutorial <tutorial/index>
    How-to guides <how-to/index>
    Reference <reference/index>
    Explanation <explanation/index>
    Changelog <changelog>
