all:

check:
	@[ -n '$(LOCAL_KEYSERVER)' ] || [ -n '${AUTOSIGN_NO_SEND_KEYS}' ] || { \
		echo "Please set LOCAL_KEYSERVER to local keyserver address for pushing,"; \
		echo "or AUTOSIGN_NO_SEND_KEYS=1 to disable pushing."; \
		exit 1; \
	}
	+$(MAKE) clean
	bash test.bash

clean:
	rm -rf gnupghome ldap.txt signed.txt to-send.txt

.PHONY: all check clean
