
Reorganize the user interaction of /cmd/kubauth/cmd/oidc/oidcserver/handle-authorizer to have a specific url for the login page GET and POST.
Take care of the complete OIDC flow.

Add session management only on oauth2/login url. Use the github.com/alexedwards/scs library

Don't use the session to store the RawQuery. As we plan to use a stateful storage for session management, it is important to reduce the number of session PUT/GET operation
In the session, store the successful user authentication result in order to have a full SSO between several OIDC applications.

implement a new Codec for SessionManager, which store its data as a JSON string


Implement a SessionManager storage based on the kubernetes ressources SsoSession.kubauth.kubotal.io. 
Assume data stored in this session will be always of the form userdb.User, 
so you can match the resources fields with the ones in the data stored in session using Put()

There is a problem: The ssosession resources use the session token as name. But a resource name must ne RFC 1123 compliant. How to solve this.

Use a reversible scheme. And implement the All() interface

I don't like the idea to have several type of token sanitize method. We can forget about reversibility, as storing original token in annotation is OK. Simplify the code by using the same transformation in all cases

----


Store token in spec instead of annotation, for All() correct behavior

Add age in all resource

Refactor naming (kube_ssosession_store !!!)
Why still ##################### memstore.New() ??
Use interface with context
Move SesssionManager build out of oidcserver (Setup in oidc.go)
Is cleanup working ?


On login, request user to 'remember me', to activate SSO
Also, let choice for a permanent or browser based session.
Update status with connected application

Implements a logout url

