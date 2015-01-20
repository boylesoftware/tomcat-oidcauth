OpenID Connect Authenticator for Apache Tomcat 8
================================================

This is an extension of the standard Apache Tomcat authenticator used for
form-based user authentication that also allows using OpenID Connect to
authenticate web-application users.

See details on OpenID Connect standard here:

http://openid.net/connect/

Also, Google supports OpenID Connect standard with the details described here:

https://developers.google.com/accounts/docs/OpenIDConnect

The goal of developing this authenticator was to allow web-applications that
rely on the container to provide form-based user authentication to transparently
start using OpenID Connect authentication as one of the available options in
addition to the standard form-based mechanism. That way, the same application
can be deployed in an environment where OpenID Connect authentication is used,
or in an environment that only uses regular form-based authentication without
making any changes to the application itself.

For more information on the authenticator see Wiki page at:

https://www.boylesoftware.com/wiki/index.php/OpenID_Connect_Authenticator_for_Tomcat