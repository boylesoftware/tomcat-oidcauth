OpenID Connect Authenticator for Tomcat
=======================================

This is an extension of the standard [Apache Tomcat](https://tomcat.apache.org)
authenticator used for form-based user authentication that uses OpenID Connect
to authenticate web-application users.

See details on OpenID Connect standard here:

http://openid.net/connect/

Also, Google supports OpenID Connect standard with the details described here:

https://developers.google.com/accounts/docs/OpenIDConnect

Introduction
------------

The goal of developing this authenticator was to allow web-applications that
rely on the container to provide form-based user authentication to transparently
use OpenID Connect authentication. That way, the same application can be
deployed in an environment where OpenID Connect authentication is used,
or in an environment that only uses regular form-based authentication without
making any changes to the application itself.

When the OpenID Connect authenticator is involved, when a client attempts to
access a protected web-application URL, the authenticator redirects the client
to the OpenID Connect authorization server (normally, with regular form-based
authentication, the authenticator forwards to the login form page). The
authorization server authenticates the user and redirects back to the
web-application's `/j_security_check` URL. When regular form-based
authentication is used, the login form submits the username and password to this
URL. The OpenID Connect authorization server returns back to this URL with a
special token, which gets validated in a server-to-server API call from the
authenticator to the authorization server and is used to retrieve the
authenticated principal information. This information is then used with the
security realm configured for the web-application to lookup the user and the
successfully authenticated request is forwarded further for processing by the
web-application as if the login form were submitted.

As mentioned above, the web-application is configured normally for form-based
authentication. For example, in the application's `web.xml`:

```xml
<login-config>
    <auth-method>FORM</auth-method>
    <realm-name>My Application</realm-name>
    <form-login-config>
        <form-login-page>/WEB-INF/jsps/login.jsp</form-login-page>
        <form-error-page>/WEB-INF/jsps/login-error.jsp</form-error-page>
    </form-login-config>
</login-config>
```

Note, that we still configure the login page and the error page. The login page
is never used if OpenID Connect authenticator is involved (but, naturally, is
still used when the web-application is deployed with the standard form-based
authenticator). The login error page is used by the OpenID Connect authenticator
when the authorization server redirects back to the web-application with the
login error (for example, the user declined to share account information with
the application on the authorization server's consent page).

Installation
------------

The authenticator single JAR can be downloaded from the Boyle Software
open-source projects Maven repository at:

http://www.boylesoftware.com/maven/repo-os/org/bsworks/catalina/authenticator/oidc/tomcat8-oidcauth/

The JAR then needs to be placed on the Tomcat's classpath. For example, it can
be copied to `$CATALINA_BASE/lib`.

Valve Configuration
-------------------

The authenticator is installed in Tomcat as a
[Valve](https://tomcat.apache.org/tomcat-8.0-doc/config/valve.html), normally on
the [Context](https://tomcat.apache.org/tomcat-8.0-doc/config/context.html)
level. For example:

```xml
<Valve className="org.bsworks.catalina.authenticator.oidc.OpenIDConnectAuthenticator"
       discoveryDocumentURL="https://my.oidcprovider.com/.well-known/openid-configuration"
       clientId="XXX"/>
```

The following authenticator valve configuration properties are available:

<dl>

<dt>discoveryDocumentURL</dt>
<dd><em>(required)</em> URL of the OpenID Connect provider's discovery document.
The discovery document describes the provider's API endpoints used during the
authentication sequence. Specifying this URL connects the authenticator to a
particular OpenID Connect provider. For example, for <em>Google</em> (including
<em>Google Apps</em>), the discovery document URL is
https://accounts.google.com/.well-known/openid-configuration.</dd>

<dt>clientId</dt>
<dd><em>(required)</em> OpenID Connect client id. This id identifies the
web-application for the OpenID Connect provider.</dd>

<dt>clientSecret</dt>
<dd><em>(optional)</em> OpenID Connect client secret. Some OpenID Connect
providers (including <em>Google</em>) require a special client secret to be
submitted together with the client id. If not specified, no such secret is
included in the calls to the OpenID Connect provider's endpoints.</dd>

<dt>hostBaseURI</dt>
<dd><em>(optional)</em> Virtual host base URI. When the authenticator redirects
the client to the OpenID Connect authorization server, it has to provide it with
the return URL, which is the application's <code>j_security_check</code> URL.
The <code>hostBaseURI</code> property is used to construct the return URL. It
must include the protocol (should always be HTTPS), the host and, if needed,
port, but not the context path. It also must not end with a slash. For example,
"https://www.example.com". If this property is not specified, the authenticator
will make an attempt to construct the URI based on the current request. In the
majority of cases, the authenticator can construct the URI correctly, so this
property is rarely used.</dd>

<dt>hostedDomain</dt>
<dd><em>(optional)</em> Some OpenID Connect providers (for example <em>Google
Apps</em>) can limit the realm of the users to a given domain. This property can
be used to specify such domain.</dd>

<dt>usernameClaim</dt>
<dd><em>(optional)</em> Claim in the
<a href="http://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
used as the username for the web-application. The default is "sub" (the subject
identifier), but often web-application use e-mail address as the username, in
which case this argument needs to be specified as "email".</dd>

<dt>httpConnectTimeout</dt>
<dd><em>(optional)</em> Timeout in milliseconds used for establishing
server-to-server HTTP connections with the OpenID Connect provider's endpoints.
The default is 5000 (5 seconds).</dd>

<dt>httpReadTimeout</dt>
<dd><em>(optional)</em> Timeout in milliseconds used for reading data in
server-to-server HTTP connections with the OpenID Connect provider's endpoints.
The default is 5000 (5 seconds).</dd>

</dl>

In addition to the attributes above, all the attributes of the standard
form-based authenticator are available as well. See more information here:

https://tomcat.apache.org/tomcat-8.0-doc/config/valve.html#Form_Authenticator_Valve

Here is an example of the valve configuration for an application that uses
*Google Apps* accounts for authentication with e-mails used as usernames:

```xml
<Valve className="org.bsworks.catalina.authenticator.oidc.OpenIDConnectAuthenticator"
       discoveryDocumentURL="https://accounts.google.com/.well-known/openid-configuration"
       clientId="XXX"
       clientSecret="XXX"
       hostedDomain="example.com"
       usernameClaim="email"/>
```

The client id and secret can be retrieved from the application configuration in
[Google Developers Console](https://console.developers.google.com/) (see OAuth
2.0 Credentials section).

Realm Configuration
-------------------

Normally, the
[Realm](https://tomcat.apache.org/tomcat-8.0-doc/config/realm.html) in Tomcat is
responsible for validating the username and password of the user attempting to
authenticate. With OpenID Connect, the password (if password-based
authentication is used) is verified by the authorization server, not the realm.
However, the authenticator still needs to lookup the authenticated user in the
realm to make sure that the user exists in the application and to get the user
roles. For the purpose of the OpenID Connect authenticator, the realm needs to
be configured in such a way, that the password is always the same as the
username (we still need the password due to limitations in the Tomcat API). For
example, if the application uses a database table for the user information and
roles, the realm configuration in the application's context might look like the
following:

```xml
<Realm className="org.apache.catalina.realm.DataSourceRealm"
       dataSourceName="jdbc/ds"
       userTable="users" userNameCol="user_name" userCredCol="user_name"
       userRoleTable="user_roles" roleNameCol="role_name"/>
```

Or, if an LDAP directory is used:

```xml
<Realm className="org.apache.catalina.realm.JNDIRealm"
       connectionURL="ldap://localhost:389"
       connectionName="cn=Manager,dc=mycompany,dc=com"
       connectionPassword="secret"
       userPattern="uid={0},ou=people,dc=mycompany,dc=com"
       userPassword="uid"
       roleBase="ou=groups,dc=mycompany,dc=com"
       roleName="cn"
       roleSearch="(uniqueMember={0})"/>
```

Note the `userCredCol` and `userPassword` attributes in the definitions of these
realms that make sure that the password is always the same as the username.