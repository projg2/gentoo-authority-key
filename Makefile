all:

check:
	rm -rf gnupghome
	umask 077 && mkdir -p gnupghome
	@echo Generating authority key ...
	GNUPGHOME=$${PWD}/gnupghome gpg --yes --quick-gen-key 'Testing Authority Key' </dev/null
	@echo Performing the initial run ...
	GNUPGHOME=$${PWD}/gnupghome bash ./autosign.bash
	@echo Performing the verification run ...
	GNUPGHOME=$${PWD}/gnupghome bash ./autosign.bash

clean:
	rm -rf gnupghome

.PHONY: all check clean
