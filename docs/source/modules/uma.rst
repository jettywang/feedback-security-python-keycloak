.. _uma:

UMA
========================


Configure client UMA
-------------------------

.. code-block:: python

    from keycloak import KeycloakOpenIDConnection
    from keycloak import KeycloakUMA

    keycloak_connection = KeycloakOpenIDConnection(
                            server_url="http://localhost:8080/",
                            realm_name="master",
                            client_id="my_client",
                            client_secret_key="client-secret")

    keycloak_uma = KeycloakUMA(connection=keycloak_connection)


Create a resource set
-------------------------

.. code-block:: python

    resource_set = keycloak_uma.resource_set_create({
                    "name": "example_resource",
                    "scopes": ["example:read", "example:write"],
                    "type": "urn:example"})

List resource sets
-------------------------

.. code-block:: python

    resource_sets = uma.resource_set_list()

Get resource set
-------------------------

.. code-block:: python

    latest_resource = uma.resource_set_read(resource_set["_id"])

Update resource set
-------------------------

.. code-block:: python

    latest_resource["name"] = "New Resource Name"
    uma.resource_set_update(resource_set["_id"], latest_resource)

Delete resource set
------------------------
.. code-block:: python

    uma.resource_set_delete(resource_id=resource_set["_id"])


Batch permission requests
-------------------------

Several permission requests can be submitted together. Overlapping scope-level
requests for the same resource are merged into one entry, while resource-level
requests are kept separate so the requested authorization never gets widened.
The response is mapped back to every original request, including duplicates,
and grants that were not requested are reported separately as
``extra_permissions``.

Permission-ticket style (one ticket request plus a token exchange):

.. code-block:: python

    requests = [
        {"resource": "reporting-api", "scopes": ["read", "write"]},
        {"resource": "reporting-api", "scopes": ["read", "export"]},
        {"resource": "billing-api"},
    ]

    result = keycloak_uma.permissions_batch(requests)
    for item in result.results:
        print(item.request.index, item.status.value, item.missing_scopes)
    print(result.network_requests)      # 2
    print(result.extra_permissions)    # grants nobody asked for

Use ``permission_ticket_batch`` when only the ticket is needed.

Token-endpoint style (a single ``response_mode=permissions`` request):

.. code-block:: python

    result = keycloak_openid.permissions_batch(token, requests)
    print(result.network_requests)      # 1

Asynchronous counterparts are available as ``a_permissions_batch`` and
``a_permission_ticket_batch``. Empty input short-circuits without any network
request.
