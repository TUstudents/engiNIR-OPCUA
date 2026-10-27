================================
Certificates: the PKI directory
================================

A server or client trusts nothing until it is told which certificates to trust. The simplest way to tell it is one PKI
directory, with the same layout as the directory store of the OPC Foundation .NET stack::

    pki/
      own/certs/       application certificate (DER) and the intermediate CA certificates of its chain
      own/private/     private key (PEM), the folder is readable by its owner only
      trusted/certs/   trusted certificates: CA certificates or self-signed application certificates
      trusted/crl/     revocation lists of the trusted CAs
      issuer/certs/    CA certificates needed to build chains, not trusted by themselves
      issuer/crl/      revocation lists of the issuer CAs
      rejected/certs/  certificates of peers that failed validation

Server and client load it with one call::

    await server.set_application_uri("urn:example:server")
    server.set_endpoint("opc.tcp://0.0.0.0:4840/example/")
    await server.set_pki_directory("pki")

    client.application_uri = "urn:example:client"
    await client.set_pki_directory("pki")
    await client.set_security(SecurityPolicyBasic256Sha256)

With ``create=True`` (the default) the folders are created. When ``own/certs`` holds no certificate, a self-signed
application certificate and its key are generated there from the application URI and the host names. An existing
certificate is never replaced. Set the application URI (and the endpoint of a server) before the call.

A certificate that fails validation is written to ``rejected/certs`` as ``<thumbprint>.der``, once per thumbprint, with
at most 100 files (the oldest are removed). Nothing in ``rejected`` is ever trusted. To trust a peer, check its
certificate, move the file to ``trusted/certs`` and call ``await server.reload_trust_store()`` (a client reads the
folders again at every connect). A revocation list in ``trusted/crl`` applies to the trusted CAs, one in ``issuer/crl``
to the issuer CAs. Revocation is checked once a list is present.

``server.set_user_pki_directory("users")`` gives the certificates of X509 user tokens the same layout (without
``own``), separate from the application certificates.

The explicit calls (``load_certificate``, ``set_trust_store(TrustStore([...], [...]))``, ...) keep working.
