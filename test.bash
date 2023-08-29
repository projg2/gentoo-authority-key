#!/bin/bash
# Authority key autosigning testcases
# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: 2019 Michał Górny
# SPDX-FileCopyrightText: 2023 Robin Johnson
if [ -z "$LOCAL_KEYSERVER" ] && [ -z "${AUTOSIGN_NO_SEND_KEYS}" ] ; then
	echo "Please set LOCAL_KEYSERVER to local keyserver address for pushing,"; 1>&2
	echo "or AUTOSIGN_NO_SEND_KEYS=1 to disable pushing."; 1>&2
	exit 1;
fi

TEST_RC=0

# For testing, keep a single tmpdir, and iterate phases.
export AUTOSIGN_TMPDIR=$(mktemp -d /tmp/autosign-test.XXXXXX)
export GNUPGHOME=$AUTOSIGN_TMPDIR/gnupghome
echo "Testing tmpdir is $AUTOSIGN_TMPDIR"

umask 077 && mkdir -p $GNUPGHOME
[ -n "${AUTOSIGN_NO_SEND_KEYS}" ] || echo "keyserver ${LOCAL_KEYSERVER}" > ${GNUPGHOME}/gpg.conf

# This is a complete hack.
DO_REVOKE_TEST=0
if [[ -z "${AUTOSIGN_FILTER}" ]]; then
	: "${AUTOSIGN_FILTER:=(&(gentooStatus=active)(gpgfingerprint=*))}"
	DO_REVOKE_TEST=1
	# All devs
	FILTER_00="${AUTOSIGN_FILTER}"
	# Exclude a few devs to trigger revoke.
	FILTER_01="(&${AUTOSIGN_FILTER}(!(uid=a*)))"
	AUTOSIGN_FILTER=$FILTER_00
	export AUTOSIGN_FILTER
fi

authuid_foo='Testing Authority Key Foo <auth-foo@example.com>'
authuid_bar='Testing Authority Key Bar <auth-bar@example.com>'

echo "Generating dummy keys (set 1)..."
# this is to ensure there are other secret keys, and we aren't just lucky with the
# code picking a random key that was the correct one for the key.
for f in $(seq 1 4) ; do
	:
	#gpg --batch --passphrase '' --quick-gen-key "Dummy Key 0x$(printf %04x $f)"
done

echo "Generating authority keys ..."
gpg -q --batch --passphrase '' --quick-gen-key "${authuid_foo}"
authfpr_foo=$(
	gpg --with-colon --list-secret-keys "${authuid_foo}" |awk -F: '($1 == "sec"){sec_k=$5 }($1 == "fpr"){fpr=$10; r= sec_k "$" ; if(match(fpr, r)){ print fpr}}'
)

gpg -q --batch --passphrase '' --quick-gen-key "${authuid_bar}"
authfpr_bar=$(
	gpg --with-colon --list-secret-keys "${authuid_bar}" |awk -F: '($1 == "sec"){sec_k=$5 }($1 == "fpr"){fpr=$10; r= sec_k "$" ; if(match(fpr, r)){ print fpr}}'
)

echo "Generating dummy keys (set 2)..."
# this is to ensure there are other secret keys, and we aren't just lucky with the
# code picking a random key that was the correct one for the key.
for f in $(seq 5 8) ; do
	:
	#gpg --batch --passphrase '' --quick-gen-key "Dummy Key <dummy-0x$(printf %04x $f)@example.com>"
done

if [[ -z "$authfpr_foo" ]] || [[ -z "$authfpr_bar" ]] || [ "$authfpr_bar" == "$authfpr_foo" ]; then
	echo "Failed to generate 2 distinct authority keys" 1>&2
	exit 1
fi

#echo "Showing all secret keys"
#gpg --list-secret-keys


echo "Performing the initial runs, for keys foo & bar ..."
n=00
gpg --with-colons --check-sig \
	--trusted-key ${authfpr_foo} \
	--trusted-key ${authfpr_bar} \
	>"${AUTOSIGN_TMPDIR}"/verification-${n}.txt
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-foo/ AUTOSIGN_GPG_LOCAL_FPR=${authfpr_foo} bash ./autosign.bash
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-bar/ AUTOSIGN_GPG_LOCAL_FPR=${authfpr_bar} bash ./autosign.bash

echo "Performing the verification run ... - should be no new signatures"
n=01
gpg --with-colons --check-sig \
	--trusted-key ${authfpr_foo} \
	--trusted-key ${authfpr_bar} \
	>"${AUTOSIGN_TMPDIR}"/verification-${n}.txt
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-foo/ AUTOSIGN_GPG_LOCAL_FPR=${authfpr_foo} bash ./autosign.bash
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-bar/ AUTOSIGN_GPG_LOCAL_FPR=${authfpr_bar} bash ./autosign.bash

n=02
gpg --with-colons --check-sig \
	--trusted-key ${authfpr_foo} \
	--trusted-key ${authfpr_bar} \
	>"${AUTOSIGN_TMPDIR}"/verification-${n}.txt

echo "Verification test: If this output is NOT identical, something changed:"
diff -NuarwbB -I '^tru'  "${AUTOSIGN_TMPDIR}"/verification-{01,02}.txt
rc=$?
[[ $rc -ne 0 ]] && echo "Verification: FAIL - Something changed after verification pass" && TEST_RC=1
[[ $rc -eq 0 ]] && echo "Verification: PASS"

[[ $DO_REVOKE_TEST -eq 0 ]] && exit 0
AUTOSIGN_FILTER=$FILTER_01
export AUTOSIGN_FILTER

echo "Performing the revocation run ... - should revoke some user"
n=03
gpg --with-colons --check-sig \
	--trusted-key ${authfpr_foo} \
	--trusted-key ${authfpr_bar} \
	>"${AUTOSIGN_TMPDIR}"/verification-${n}.txt
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-foo/ AUTOSIGN_GPG_LOCAL_FPR=${authfpr_foo} bash ./autosign.bash
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-bar/ AUTOSIGN_GPG_LOCAL_FPR=${authfpr_bar} bash ./autosign.bash

echo "Validating revocation"
n=04
gpg --with-colons --check-sig \
	--trusted-key ${authfpr_foo} \
	--trusted-key ${authfpr_bar} \
	>"${AUTOSIGN_TMPDIR}"/verification-${n}.txt

echo "Revocation compare: If this does NOT show output, then the revoke failed"
# Check the developers starting with "a", who should have been revoked.
diff -NuarwbB \
	<(grep -E -e '^uid:.:.*\<a[0-9a-fA-Z.]+@gentoo.org' <"${AUTOSIGN_TMPDIR}"/verification-03.txt) \
	<(grep -E -e '^uid:.:.*\<a[0-9a-fA-Z.]+@gentoo.org' <"${AUTOSIGN_TMPDIR}"/verification-04.txt) \
	-I '^tru'
rc=$?
[[ $rc -ne 0 ]] && echo "FAIL - Revocation pass did not revoke..." && TEST_RC=1
if [[ $rc -eq 0 ]]; then
	grep -sq -E -e '^uid:[mfus]:.*\<a[0-9a-fA-Z.]+@gentoo.org' <"${AUTOSIGN_TMPDIR}"/verification-04.txt \
		&& rc=1 \
		&& echo "FAIL - Some uid=a* developer was still signed, when not expected..." \
		&& TEST_RC=1
fi
[[ $rc -eq 0 ]] && echo "Revocation: PASS"

exit $TEST_RC
