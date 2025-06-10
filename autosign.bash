#!/usr/bin/env bash
# Authority key autosigning script
# (c) 2019 Michał Górny
# 2-clause BSD license

die() {
	echo "${@}" >&2
	exit 1
}

# Import key updates.
refresh_keys() {
	# we trust qa-scripts to refresh them for us
	wget -q -O - https://qa-reports.gentoo.org/output/active-devs.gpg |
		gpg -q --import || die "Failed to refresh keys"
}

# Get UID-fingerprint mapping from LDAP, for active devs.
get_ldap() {
	local l uid= fpr system
	while read l; do
		case ${l} in
			'dn: uid='*',ou=devs,dc=gentoo,dc=org')
				uid=${l#dn: uid=}
				uid=${uid%%,*}
				system=0
				[[ -n ${uid} ]] || die "Unable to parse dn: ${l}"
				;;
			'dn: uid='*',ou=system,dc=gentoo,dc=org')
				uid=${l#dn: uid=}
				uid=${uid%%,*}
				system=1
				[[ -n ${uid} ]] || die "Unable to parse dn: ${l}"
				;;
			'gpgfingerprint: '*)
				# skip services for now
				[[ ${system} == 1 ]] && continue
				[[ -n ${uid} ]] || die "gpgfingerprint without UID?"
				fpr=${l#gpgfingerprint: }
				[[ ${#fpr} -eq 40 ]] ||
					die "Invalid gpgfingerprint (uid=${uid}): ${l}"
				printf '%s@gentoo.org\t%s\n' "${uid,,}" "${fpr}"
				;;
			'')
				uid=
				;;
			*)
				die "Unknown LDAP data: ${l}"
				;;
		esac
	done < <(ldapsearch -Z -D '' -LLL "${AUTOSIGN_FILTER:-(gentooStatus=active)}" gpgfingerprint ||
		die "LDAP query failed")
}

# Get UID-fingerprint list of all currently trusted keys.
get_signed_keys() {
	local l keyid= fpr= trust uid email
	while read l; do
		case ${l} in
			# start of new key
			pub:*)
				keyid=${l#pub:*:*:*:}
				keyid=${keyid%%:*}
				fpr=
				[[ -n ${keyid} ]] || die "Unable to parse keyid: ${l}"
				;;
			# fingerprint, should follow pub: immediately
			fpr:*)
				# skip if we already got one (subkeys)
				[[ -n ${fpr} ]] && continue
				fpr=${l#fpr:::::::::}
				fpr=${fpr%%:*}
				[[ -n ${fpr} ]] || die "Unable to parse fpr: ${l}"
				[[ ${fpr:(-16)} == ${keyid} ]] ||
					die "fpr/keyid mismatch: ${fpr} / ${keyid}"
				;;
			uid:*)
				[[ -n ${fpr} ]] || die "UID without fpr: ${l}"
				trust=${l#uid:}
				uid=${trust#?::::*::*::}
				trust=${trust%%:*}
				uid=${uid%%:*}
				email=${uid#*<}
				email=${email%%>*}
				[[ -n ${trust} && -n ${email} ]] ||
					die "Unable to parse uid: ${l}"
				[[ ${trust} == f ]] &&
					printf "%s\t%s\n" "${email,,}" "${fpr}"
				;;
		esac
	done < <(gpg --with-colons --list-keys)
}

# Revoke the specified UID signature.
# Usage: revoke_sig <key-fpr> <uid>
revoke_sig() {
	local key=${1}
	local uid=${2}

	echo "${uid}: Revoking signature on key ${key}"
	# TODO: support revoking only one uid?
	# (NB: will this ever happen?)
	timeout 60 expect - <<-EOF || die "revoking signature failed"
		spawn gpg --edit-key ${key}
		expect "gpg>"
		send "revsig\n"
		while (1) {
			expect {
				"Create a revocation certificate for this signature?"
					{ send "y\n" }
				"Are you sure you still want to revoke it?"
					{ send "n\n" }
				"Really create the revocation certificates?"
					break
			}
		}
		send "y\n"
		expect "Your decision?"
		send "4\n"
		expect ">"
		send "\n"
		expect "Is this okay?"
		send "y\n"
		expect "gpg>"
		send "save\n"
		expect eof
	EOF
}

# Sign the specified UID on specified key.
# Usage: sign_key <key-fpr> <uid>
sign_key() {
	local key=${1}
	local sign_uid=${2}
	local ret=1

	# verify whether the key is suitable for signing
	local l trust uid email uids=() need_full=0
	while read l; do
		case ${l} in
			pub:[er]:*)
				# skip expired key
				return 1
				;;
			uid:*)
				trust=${l#uid:}
				uid=${trust#?::::*::*::}
				trust=${trust%%:*}
				uid=${uid%%:*}
				email=${uid#*<}
				email=${email%%>*}
				[[ -n ${trust} && -n ${email} ]] ||
					die "Unable to parse uid: ${l}"
				[[ ${email,,} == ${sign_uid,,} && ${trust} != [er] ]] &&
					uids+=( "=${uid}" )
				# if there are revoked UIDs, they may collide
				[[ ${trust} == [er] ]] && need_full=1
				;;
		esac
	done < <(gpg --no-auto-check-trustdb --with-colons --list-keys "${key}" 2>/dev/null)

	if [[ ${#uids[@]} -eq 0 ]]; then
#		echo "${sign_uid}: no @g.o UID (${key})"
		return 1
	elif [[ ${#uids[@]} -eq 1 && ${need_full} -eq 0 ]]; then
		# if UID is unambiguous, use e-mail
		# (because people really like to put random non-formattable
		# stuff into UIDs)
		uids=( "${sign_uid}" )
	fi

	echo "${sign_uid}: signing new key ${key}"
	for uid in "${uids[@]}"; do
		gpg --no-auto-check-trustdb \
			--cert-policy-url https://www.gentoo.org/glep/glep-0079.html \
			--default-cert-expire 1y \
			--force-sign-key \
			--quick-sign-key "${key}" "${uid}" && ret=0
	done

	return "${ret}"
}

main() {
	[[ -n ${GNUPGHOME} ]] || die "Refusing to run with GNUPGHOME unset!"

	# avoid running with old agent
	gpgconf --kill all

	refresh_keys
	get_ldap | sort -u > ldap.txt || die 'failure writing ldap.txt'
	get_signed_keys | sort -u > signed.txt || die 'failure writing signed.txt'

	local k uid
	# revoke signatures on old keys
	while read uid k; do
		if revoke_sig "${k}" "${uid}"; then
			echo "${k}" >> to-send.txt || die 'failure writing to-send.txt'
		fi
	done < <(comm -23 signed.txt ldap.txt)

	# sign new keys
	while read uid k; do
		if sign_key "${k}" "${uid}"; then
			echo "${k}" >> to-send.txt || die 'failure writing to-send.txt'
		fi
	done < <(comm -13 signed.txt ldap.txt)

	gpg -q --check-trustdb

	if [[ ! ${AUTOSIGN_NO_SEND_KEYS} ]]; then
		# send key updates to the keyserver
		local retries=0
		while [[ -s to-send.txt ]]; do
			if gpg --send-keys $(head -n 10 to-send.txt); then
				tail -n +11 to-send.txt > to-send.txt.tmp &&
				mv to-send.txt.tmp to-send.txt || die 'failure writing to-send.txt'
			else
				[[ $(( ++retries )) -ge 5 ]] && die 'send failure limit exceeded'
			fi
		done
	fi
}

main "${@}"
