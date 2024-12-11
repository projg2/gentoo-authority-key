# Gentoo Authority Key autosigning script

Given a list of trusted fingerprints from Gentoo's LDAP, compare the keyring
for the presence of absence of a signature from an Authority key.

- Revoke signatures for keys where the LDAP trust has been removed
- Add signatures for keys where LDAP trust has been added
- Renew signatures where the prior signature has expired

## Testing
See `test.bash` for implementation.

Requirements:
- Must run on gentoo.org system w/ LDAP access

### Test process:
1. generate two authority keys
2. sign once [implicit keyring import]
3. check exactly 1 signatures is present per authority
4. sign again
5. check exactly 1 signatures is present per authority [to avoid unlimited growth]
6. revoke a subset of signatures
7. ensure the keys are now shown as untrusted
