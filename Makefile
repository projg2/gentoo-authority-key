all:

check:
	@[ -n '$(LOCAL_KEYSERVER)' ] || [ -n '${AUTOSIGN_NO_SEND_KEYS}' ] || { \
		echo "Please set LOCAL_KEYSERVER to local keyserver address for pushing,"; \
		echo "or AUTOSIGN_NO_SEND_KEYS=1 to disable pushing."; \
		exit 1; \
	}
	+$(MAKE) clean
	umask 077 && mkdir -p gnupghome
	[ -n '${AUTOSIGN_NO_SEND_KEYS}' ] || echo 'keyserver $(LOCAL_KEYSERVER)' > gnupghome/gpg.conf
	@echo Generating authority key ...
	GNUPGHOME=$${PWD}/gnupghome gpg --batch --passphrase '' --quick-gen-key 'Testing Authority Key'
	@echo Performing the initial run ...
	GNUPGHOME=$${PWD}/gnupghome bash ./autosign.bash
	@echo Performing the verification run ...
	GNUPGHOME=$${PWD}/gnupghome bash ./autosign.bash

clean:
	rm -rf gnupghome ldap.txt signed.txt to-send.txt

.PHONY: all check clean
