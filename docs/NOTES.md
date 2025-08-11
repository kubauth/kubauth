
# About userdb module access

The userdb web server does not provide access control mechanism. 
This is not a problem as it is intended to be bound on localhost.

If it as to be exposed to others pod, then a sidecar container should be added, to provide authentication and maybe TLS

Note then binding on 0.0.0.0 is still possible using flags. But, this is intended to be used only in test/dev stage.


# Claims 

For a given users claims map is build the following:
- First, if user belong to one or several groups, a claim 'groups' with a list of its groups is set
- Then groups are accessed in alphabetic order and for each one, claims (if any) are merged on top (overwrite) of existing ones.
- The the user's claims are merged on top (overwrite) of exitsing one.

This means if a 'groups' claim is defined explicitly on a group or on the user, it will overwrite the one built from the group list.

