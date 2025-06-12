#!/bin/bash
# Authority key autosigning testcases
# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: 2019 Michał Górny
# SPDX-FileCopyrightText: 2023-2024 Robin Johnson
die() {
	local rc=${1}
	shift
	echo "${*}" 1>&2
	[[ -n ${AUTOSIGN_TMPDIR} ]] && echo "Testing tmpdir is ${AUTOSIGN_TMPDIR}" 1>&2
	exit "${rc}"
}

if [[ -z ${LOCAL_KEYSERVER} && -z ${AUTOSIGN_NO_SEND_KEYS} ]]; then
	die 1 "Please set LOCAL_KEYSERVER to local keyserver address for pushing, or AUTOSIGN_NO_SEND_KEYS=1 to disable pushing."
fi

TEST_RC=0

# For testing, keep a single tmpdir, and iterate phases.
AUTOSIGN_TMPDIR=$(mktemp -d /tmp/autosign-test.XXXXXX) || die 2 "Failed to create testing directory"
GNUPGHOME=${AUTOSIGN_TMPDIR}/gnupghome
export AUTOSIGN_TMPDIR GNUPGHOME
echo "Testing tmpdir is ${AUTOSIGN_TMPDIR}"

umask 077 && mkdir -p "${GNUPGHOME}"
[[ -n ${AUTOSIGN_NO_SEND_KEYS} ]] || echo "keyserver ${LOCAL_KEYSERVER}" >"${GNUPGHOME}"/gpg.conf

# This is a complete hack.
DO_REVOKE_TEST=0
if [[ -z "${AUTOSIGN_FILTER}" ]]; then
	: "${AUTOSIGN_FILTER:=(&(gentooStatus=active)(gpgfingerprint=*))}"
	DO_REVOKE_TEST=1
	# All devs
	FILTER_00="${AUTOSIGN_FILTER}"
	# Exclude a few devs to trigger revoke.
	FILTER_01="(&${AUTOSIGN_FILTER}(!(uid=a*)))"
	AUTOSIGN_FILTER=${FILTER_00}
	export AUTOSIGN_FILTER
fi

authuid_foo='Testing Authority Key Foo <auth-foo@example.com>'
authuid_bar='Testing Authority Key Bar <auth-bar@example.com>'

echo "Generating dummy keys (set 1)..."
# this is to ensure there are other secret keys, and we aren't just lucky with the
# code picking a random key that was the correct one for the key.
for f in {1..4}; do
	gpg --batch --passphrase '' --quick-gen-key "Dummy Key 0x$(printf %04x "${f}")"
done

gpg_colon_get_sec_fpr() {
	# relies on the ordering that fingerprints of a key are strictly listed after it.
	awk -F: '($1 == "sec"){sec_k=$5 }($1 == "fpr"){fpr=$10; r= sec_k "$" ; if(match(fpr, r)){ print fpr}}'
}

echo "Generating authority keys ..."
gpg -q --batch --passphrase '' --quick-gen-key "${authuid_foo}"
authfpr_foo=$(
	gpg --with-colon --list-secret-keys "${authuid_foo}" | gpg_colon_get_sec_fpr
)

gpg -q --batch --passphrase '' --quick-gen-key "${authuid_bar}"
authfpr_bar=$(
	gpg --with-colon --list-secret-keys "${authuid_bar}" | gpg_colon_get_sec_fpr
)
if [[ ! ${authfpr_bar} =~ ^[A-F0-9]{40}$ ]]; then
	echo "Failed to generate authority key 'bar', expected HEX{40}, got fingerprint ${authfpr_bar}" 1>&2
	TEST_RC=1
fi
if [[ ! ${authfpr_foo} =~ ^[A-F0-9]{40}$ ]]; then
	echo "Failed to generate authority key 'foo', expected HEX{40}, got fingerprint ${authfpr_foo}" 1>&2
	TEST_RC=1
fi
[[ ${TEST_RC} -ne 0 ]] && die "${TEST_RC}" ""

echo "Generating dummy keys (set 2)..."
# this is to ensure there are other secret keys, and we aren't just lucky with the
# code picking a random key that was the correct one for the key.
for f in {5..8}; do
	gpg --batch --passphrase '' --quick-gen-key "Dummy Key <dummy-0x$(printf %04x "${f}")@example.com>"
done

if [[ -z "${authfpr_foo}" || -z "${authfpr_bar}" || "${authfpr_bar}" == "${authfpr_foo}" ]]; then
	die 1 "Failed to generate 2 distinct authority keys"
fi

#echo "Showing all secret keys"
#gpg --list-secret-keys

n=00
gpg --with-colons --check-sig \
	--trusted-key "${authfpr_foo}" \
	--trusted-key "${authfpr_bar}" \
	>"${AUTOSIGN_TMPDIR}"/verification-${n}.txt
if grep -i -e 'uid.*@gentoo' "${AUTOSIGN_TMPDIR}"/"verification-${n}.txt"; then
	die 1 "Found @gentoo keys in the output when only the authority & dummy keys should have been present, see verification-${n}.txt"
fi

# TODO: a nice improvement here for testing would be to import-only Gentoo keys but NOT sign them yet
# to assert that they are *NOT* yet signed.

echo "Performing the initial runs, for keys foo & bar ..."
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-foo/ AUTOSIGN_GPG_LOCAL_FPR="${authfpr_foo}" bash ./autosign.bash
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-bar/ AUTOSIGN_GPG_LOCAL_FPR="${authfpr_bar}" bash ./autosign.bash

n=01
gpg --with-colons --check-sig \
	--trusted-key "${authfpr_foo}" \
	--trusted-key "${authfpr_bar}" \
	>"${AUTOSIGN_TMPDIR}"/verification-${n}.txt

echo "Signing test: uids should now be trusted after, but not before"
diff -NuarwbB -I '^tru' "${AUTOSIGN_TMPDIR}"/verification-{00,01}.txt >"${AUTOSIGN_TMPDIR}"/diff-00-01.patch
count_before=$(grep -c -e '^uid:f:' "${AUTOSIGN_TMPDIR}"/verification-00.txt)
count_after=$(grep -c -e '^uid:f:' "${AUTOSIGN_TMPDIR}"/verification-01.txt)
if [[ ${count_before} -ne 0 || ${count_after} -eq ${count_before} ]]; then
	die 1 "FAIL: UIDs did not become trusted as expected"
fi

echo "Performing the verification run ... - should be no new signatures"
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-foo/ AUTOSIGN_GPG_LOCAL_FPR="${authfpr_foo}" bash ./autosign.bash
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-bar/ AUTOSIGN_GPG_LOCAL_FPR="${authfpr_bar}" bash ./autosign.bash

n=02
gpg --with-colons --check-sig \
	--trusted-key "${authfpr_foo}" \
	--trusted-key "${authfpr_bar}" \
	>"${AUTOSIGN_TMPDIR}"/verification-${n}.txt

echo "2nd-run Verification test: Output other than 'tru' should be identical"
diff -NuarwbB -I '^tru' "${AUTOSIGN_TMPDIR}"/verification-{01,02}.txt >"${AUTOSIGN_TMPDIR}"/diff-01-02.patch
rc=$?
cat "${AUTOSIGN_TMPDIR}"/diff-01-02.patch
if [[ ${rc} -eq 0 ]]; then
	echo "Verification: PASS"
else
	echo "Verification: FAIL - Something changed after verification pass"
	TEST_RC=1
fi

if [[ ${DO_REVOKE_TEST} -eq 0 ]]; then
	die "${TEST_RC}" "Testing tmpdir is ${AUTOSIGN_TMPDIR}"
fi

# Start the revocation tests
# revoke all users starting with "a"
AUTOSIGN_FILTER=${FILTER_01}
export AUTOSIGN_FILTER

echo "Performing the revocation run ... - should revoke some user"
n=03
gpg --with-colons --check-sig \
	--trusted-key "${authfpr_foo}" \
	--trusted-key "${authfpr_bar}" \
	>"${AUTOSIGN_TMPDIR}"/verification-${n}.txt
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-foo/ AUTOSIGN_GPG_LOCAL_FPR=${authfpr_foo} bash ./autosign.bash
AUTOSIGN_TMPDIR=${AUTOSIGN_TMPDIR}/${n}-bar/ AUTOSIGN_GPG_LOCAL_FPR=${authfpr_bar} bash ./autosign.bash

echo "Validating revocation"
n=04
gpg --with-colons --check-sig \
	--trusted-key "${authfpr_foo}" \
	--trusted-key "${authfpr_bar}" \
	>"${AUTOSIGN_TMPDIR}"/verification-${n}.txt

echo "Revocation compare: If this does NOT show output, then the revoke failed"
# Check the developers starting with "a", who should have been revoked.
diff -NuarwbB \
	<(grep -E -e '^uid:.:.*\<a[^@]+@gentoo.org>:' <"${AUTOSIGN_TMPDIR}"/verification-03.txt) \
	<(grep -E -e '^uid:.:.*\<a[^@]+@gentoo.org>:' <"${AUTOSIGN_TMPDIR}"/verification-04.txt) \
	-I '^tru:' \
	>"${AUTOSIGN_TMPDIR}"/diff-03-04.txt
cat "${AUTOSIGN_TMPDIR}"/diff-03-04.txt
# Check closely that it WAS actually revoked.
# No developers with "a" should be trusted anymore
if grep -E -e '^uid:[mfus]:.*<a[^@]+@gentoo.org>:' <"${AUTOSIGN_TMPDIR}"/verification-04.txt; then
	echo "Revocation: FAIL - Some uid=a* developer was still signed, when not expected..."
	TEST_RC=1
# And make sure they were actually removed.
elif grep -sq -e '^-uid:[mf]:' "${AUTOSIGN_TMPDIR}"/diff-03-04.txt && grep -sq -e '^+uid:[-q]:' "${AUTOSIGN_TMPDIR}"/diff-03-04.txt; then
	echo "Revocation: PASS"
else
	echo "FAIL - Revocation pass did not revoke..."
	TEST_RC=1
fi

die "${TEST_RC}" ""
