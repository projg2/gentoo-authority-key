all:

check:
	@[ -n '$(LOCAL_KEYSERVER)' ] || { \
		echo "Please set LOCAL_KEYSERVER to local keyserver address for pushing!"; \
		exit 1; \
	}
	+$(MAKE) clean
	umask 077 && mkdir -p gnupghome
	echo 'keyserver $(LOCAL_KEYSERVER)' > gnupghome/gpg.conf
	@echo Generating authority key ...
	GNUPGHOME=$${PWD}/gnupghome gpg --yes --quick-gen-key 'Testing Authority Key' </dev/null
	@echo Performing the initial run ...
	GNUPGHOME=$${PWD}/gnupghome bash ./autosign.bash
	@echo Performing the verification run ...
	GNUPGHOME=$${PWD}/gnupghome bash ./autosign.bash

clean:
	rm -rf gnupghome ldap.txt signed.txt to-send.txt

.PHONY: all check clean
