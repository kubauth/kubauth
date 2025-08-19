
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


An optional field 'fullName' has been added in SsoSession resources and also in userdb.User struct. Handle the storage of this value

A required 'WebToken' field has been added in SsoSession resources. Use it to store the scs token, instead of using annotation.

Rename KubeSsoSessionStore to KubeSsoStore


Implement expired SsoSession cleanup, using same logic as scs.memstore.cleanup.
Implement this cleaner as a Runnable, to be set under the manager control, in oidc.go 

I have added a flags.cleanupPeriod configuration value. Use it and disable cleanup if value is 0

Rename SsoCleaner to KubeSsoCleaner and cleaner.go to kubessocleaner.go

Inject context in KubeSsoStore by implementing CtxStore and IterableCtxStore instead of Store and IterableStore

Complete the oidcserver.handleLogout function to retrieve and delete the corresponding SsoSession 


Complete the oidcserver.handleIndex function to display a page listing oidcClient in a user-friendly way.
Only oidcClient with a non null 'name' and 'entryUrl' attribute will be listed.
Each display entry will include 'name', 'description'. The 'name' attribute being a link on 'entryURL' value.
Style will be the same as the resource/templates/login.gohtml. Put the css in a separate file 

----



Add a redirect on logout url in client definition, and globally if no client id

On login, request user to 'remember me', to activate SSO
Update status with connected application

An index page listing registered apps
