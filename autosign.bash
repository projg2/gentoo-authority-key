#!/usr/bin/env bash
# Authority key autosigning script
# SPDX-License-Identifier: BSD-2-Clause
# SPDX-FileCopyrightText: 2019 Michał Górny
# SPDX-FileCopyrightText: 2023 Robin Johnson

: "${KEYRING_URL:=https://qa-reports.gentoo.org/output/active-devs.gpg}"
: "${AUTOSIGN_FILTER:=(gentooStatus=active)}"
# At the minimum, make (almost) every call to GPG with the same timestamp, at
# the START of this script.
# The script takes a few seconds to run, so this makes all new
# signatures/revokes be at exactly the same timestamp.
# "almost" => see the exception where we list valid signatures at a time in the
# future, to see what signatures would have expired.
: "${FAKED_EPOCH:=$(date +%s)!}"

# Used for trust args to gpg calls
export -a trust_args

# Baseline GPG
gpgcmd=(
	gpg
	--quiet
	--no-auto-check-trustdb
	--faked-system-time="${FAKED_EPOCH}"
)

warn() {
	echo "${@}" >&2
}

die() {
	warn "${@}"
	exit 1
}

# Import key updates.
refresh_keys() {
	# we trust qa-scripts to refresh them for us
	wget -q -O keyring.gpg "${KEYRING_URL}" || die "Failed to fetch keyring"
	"${gpgcmd[@]}" -q --import keyring.gpg || die "Failed to import keyring"
}

# Get UID-fingerprint mapping from LDAP, for active devs.
get_ldap() {
	local l uid='' fpr='' system=''
	local f='ldapraw.txt'
	get_ldap_raw >"${f}"
	while read l; do
		case "${l}" in
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
	done <"${f}"
}

get_ldap_raw() {
	h="$(hostname --fqdn)"
	# This needs some weird quoting because SSH.
	if [[ "${h%.gentoo.org}" == "${h}" ]]; then
		ssh dev.gentoo.org "ldapsearch -Z -D '' -LLL '${AUTOSIGN_FILTER}' gpgfingerprint"
		rc=$?
	else
		ldapsearch -Z -D '' -LLL "${AUTOSIGN_FILTER}" gpgfingerprint
		rc=$?
	fi
	[[ $rc -ne 0 ]] && die "LDAP query failed"
}

# Get UID-fingerprint list of all currently trusted keys.
get_signed_keys() {
	local -a GPGREC
	local l keyid='' fpr=''
	local uid_validity='' uid_string='' uid_email=''
	#local sig_validity= sig_class= sig_issuer=

	op=list-keys
	#op=check-sigs

	# Use a date 1 week into the future, to see what signatures WILL have
	# expired, and need refreshing before then.
	# TODO: is 1 week enough?
	future_epoch="$(( $FAKED_EPOCH + (86400 * 7) ))!"

	local f=${op}.txt
	"${gpgcmd[@]}" \
		--with-colons \
		"${trust_args[@]}" \
		--faked-system-time="$future_epoch" \
		--${op} \
		>${f}

	while read l; do
		# split the gpg line correctly into fields
		# Per GPG DETAILS, there will never be a raw : inside a field, it will instead be encoded as \x3a
		# TODO: as a seperate pass, apply a C decode to convert the above back.
		IFS=':' read -ra GPGREC <<< "$l"

		# Be a terrible programmer: the docs have fields numbered from 1
		# So shift up the entire array by one position
		i=${#GPGREC[@]}
		while [[ $i -ge 0 ]]; do
			GPGREC[i+1]="${GPGREC[i]}"
			let i=i-1
		done
		GPGREC[0]='INVALID'

		case ${GPGREC[1]} in
			# start of new key
			pub)
				keyid=${GPGREC[5]}
				fpr=
				uid_validity=
				uid_string=
				uid_email=
				#sig_validity=
				#sig_class=
				#sig_issuer=
				[[ -n ${keyid} ]] || die "Unable to parse keyid: ${l}"
				;;
			# fingerprint, should follow pub: immediately
			fpr)
				# skip if we already got one (subkeys)
				[[ -n ${fpr} ]] && continue
				fpr=${GPGREC[10]}
				[[ -n ${fpr} ]] || die "Unable to parse fpr: ${l}"
				[[ ${fpr:(-16)} == "${keyid}" ]] ||
					die "fpr/keyid mismatch: ${fpr} / ${keyid}"
				;;
			uid)
				[[ -n ${fpr} ]] || die "UID without fpr: ${l}"
				# Start of a new uid means any old sig is not applicable.
				#sig_validity=
				#sig_class=
				#sig_issuer=
				# Parse the uid
				uid_validity=${GPGREC[2]}
				uid_string=${GPGREC[10]}
				uid_email=${uid_string#*<}
				uid_email=${uid_email%%>*}
				if [[ -z ${uid_validity} ]] || [[ -z ${uid_email} ]]; then
					warn "Unable to parse uid: ${l}"
					continue
				fi
				# The uid validity *should* be 'f' if signed by the trusted key.
				# & still valid (not revoked or expired).
				# TODO: under what conditions might it be (m)arginally valid or (u)ltimately valid?
				[[ ${uid_validity} != f ]] && continue
				[[ ${op} == list-keys ]] && printf "%s\t%s\n" "${uid_email,,}" "${fpr}"
				;;
			# TODO: for use with check-sigs
			# Sig will always follow uids, but is only present if we make this be --check-sigs
			#sig)
			#	[[ -n ${fpr} ]] || die "sig without fpr: ${l}"
			#	[[ -n ${uid_email} ]] || die "sig without uid: ${l}"
			#	sig_validity=${GPGREC[2]}
			#	sig_class=${GPGREC[11]}
			#	sig_issuer=${GPGREC[13]}
			#	# Skip invalid signatures
			#	[[ ${sig_validity} != "!" ]] && continue
			#	# Skip other signature classes
			#	# 1[0123]x => match a subset of RFC4880 signatures
			#	# x = must be exportable
			#	# 0x10 = generic
			#	# 0x11 = persona
			#	# 0x12 = casual
			#	# 0x13 = positive
			#	# https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1
			#	# TODO: right now this code sets code 0x10 (generic),
			#	# whereas 0x11 Persona might be more applicable in future.
			#	case ${sig_class} in
			#		1[0123]x) ;;
			#		*) continue ;;
			#	esac
			#	# Skip signatures from another issuer
			#	[ ${sig_issuer} != ${AUTOSIGN_GPG_LOCAL_FPR} ] && continue

			#	# good signature at this point.
			#	printf "%s\t%s\n" "${uid_email,,}" "${fpr}"
			#	;;
		esac
	# Checking the signatures is important, don't just get a list of them.
	done <"${f}"
}

# Revoke the specified UID signature.
# Usage: revoke_sig <key-fpr> <uid>
revoke_sig() {
	local key=${1}
	local uid=${2}
	local _gpgcmd=( "${gpgcmd[@]}" )
	_gpgcmd+=( "${trust_args[@]}" )

	echo "${uid}: Revoking signature on key ${key}"
	"${_gpgcmd[@]}" \
		-q \
		--quick-revoke-sig \
		"${key}" \
		"${AUTOSIGN_GPG_LOCAL_FPR}" \
		"${uid}"
}

# Sign the specified UID on specified key.
# Usage: sign_key <key-fpr> <uid>
sign_key() {
	local key=${1}
	local sign_uid=${2}
	local ret=1

	local f=sign-key-${key}.txt

	"${gpgcmd[@]}" \
		"${trust_args[@]}" \
		--with-colons \
		--list-keys "${key}" \
		2>/dev/null >"${f}"

	# verify whether the key is suitable for signing
	local l trust uid email uids=() need_full=0
	while read l; do
		# split the gpg line correctly into fields
		# Per GPG DETAILS, there will never be a raw : inside a field, it will instead be encoded as \x3a
		# TODO: as a seperate pass, apply a C decode to convert the above back.
		IFS=':' read -ra GPGREC <<< "$l"

		# Be a terrible programmer: the docs have fields numbered from 1
		# So shift up the entire array by one position
		i=${#GPGREC[@]}
		while [[ $i -ge 0 ]]; do
			GPGREC[i+1]="${GPGREC[i]}"
			let i=i-1
		done
		GPGREC[0]='INVALID'

		case ${GPGREC[1]} in
			pub)
				# skip expired key
				# skip revoked key
				[[ ${GPGREC[2]} =~ [er] ]] && return 1
				;;
			uid)
				trust=${GPGREC[2]}
				uid=${GPGREC[10]}
				email=${uid#*<}
				email=${email%%>*}
				[[ -n ${trust} && -n ${email} ]] ||
					die "Unable to parse uid: ${l}"
				[[ "${email,,}" == "${sign_uid,,}" && ${trust} != [er] ]] &&
					uids+=( "=${uid}" )
				# if there are revoked UIDs, they may collide
				[[ ${trust} =~ [er] ]] && need_full=1
				;;
		esac
	done <"${f}"

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
		"${gpgcmd[@]}" \
			--cert-policy-url https://www.gentoo.org/glep/glep-0079.html \
			--default-cert-expire 1y \
			"${trust_args[@]}" \
			--quiet --batch --no-tty \
			--quick-sign-key "${key}" "${uid}" && ret=0
	done

	return "${ret}"
}

get_localuser_fpr() {
	local fpr seen_sec=0
	local f=secret-keys.txt

	"${gpgcmd[@]}" --with-colons --list-secret-keys >${f}

	while read l; do
		# split the gpg line correctly into fields
		# Per GPG DETAILS, there will never be a raw : inside a field, it will instead be encoded as \x3a
		# TODO: as a seperate pass, apply a C decode to convert the above back.
		IFS=':' read -ra GPGREC <<< "$l"
		# Be a terrible programmer: the docs have fields numbered from 1
		# So shift up the entire array by one position
		i=${#GPGREC[@]}
		while [[ $i -ge 0 ]]; do
			GPGREC[i+1]="${GPGREC[i]}"
			let i=i-1
		done
		GPGREC[0]='INVALID'

		case ${GPGREC[1]} in
			sec) fpr='' ; let seen_sec=seen_sec+1 ;;
			fpr) fpr=${GPGREC[10]} ;;
		esac
	done <"${f}"
	case "$seen_sec" in
		0) die "No secret keys present for authority signing, is GNUPGHOME correct?" ;;
		1) echo "$fpr" ;;
		*) die "Multiple secret keys present for authority signing, specify correct key with AUTOSIGN_GPG_LOCAL_FPR" ;;
	esac
	return 0
}

main() {
	[[ -n ${GNUPGHOME} ]] || die "Refusing to run with GNUPGHOME unset!"

	# avoid running with old agent
	gpgconf --kill all

	if [[ -n "${AUTOSIGN_TMPDIR}" ]]; then
		TMPDIR=${AUTOSIGN_TMPDIR}
		mkdir -p "${TMPDIR}"
		: "${CLEANUP_TMPDIR:=0}"
	else
		TMPDIR=$(mktemp -d)
		: "${CLEANUP_TMPDIR:=1}"
	fi
	# Setup the cleaning.
	if [[ $CLEANUP_TMPDIR -eq 1 ]]; then
		trap "rm -rf $TMPDIR" INT TERM EXIT
	else
		echo "TMPDIR is at $TMPDIR with cleanup disabled"
	fi

	export TMPDIR
	cd "$TMPDIR" || die "Failed to setup unique TMPDIR"

	# A trusted user was NOT specified. So check the keyring and find it.
	if [[ -z "${AUTOSIGN_GPG_LOCAL_FPR}" ]]; then
		AUTOSIGN_GPG_LOCAL_FPR=$(get_localuser_fpr)
	fi
	[[ -z "${AUTOSIGN_GPG_LOCAL_FPR}" ]] && die "Failed to find fingerprint for local key to sign with"

	# If the key ends with a ! it's special GPG syntax for subkeys
	# We need it for local-user, but not other fields
	_AUTOSIGN_GPG_LOCAL_FPR=${AUTOSIGN_GPG_LOCAL_FPR%!}
	trustdb=trustdb-${_AUTOSIGN_GPG_LOCAL_FPR}
	# Explicitly remove the trustdb, as we will re-calculate it.
	rm -f "$trustdb"
	# If an explicit local user was set, ignore all other keys for calculating
	# trust.
	#
	# do it specifically by creating a new trustdb for that localkey, and
	# setting only that localkey to trusted in the trustdb.
	#
	# The local user MUST be specified as a full fingerprint, for matching &
	# security reasons.
	trust_args=(
		--trust-model pgp
		--trusted-key "${_AUTOSIGN_GPG_LOCAL_FPR}"
		--trustdb-name "${trustdb}"
		--local-user "${AUTOSIGN_GPG_LOCAL_FPR}"
		--default-key "${AUTOSIGN_GPG_LOCAL_FPR}"
	)

	refresh_keys

	# Check the trustdb now that we have imported the keys.
	"${gpgcmd[@]}" -q --check-trustdb

	get_ldap | sort -u > ldap.txt || die 'failure writing ldap.txt'
	get_signed_keys | sort -u > signed.txt || die 'failure writing signed.txt'

	# Items ONLY in ldap => need to sign
	comm -13 signed.txt ldap.txt >to-sign.txt
	# Items ONLY in signed => need to revoke
	comm -23 signed.txt ldap.txt >to-revoke.txt

	local k uid
	# revoke signatures on old keys
	while IFS=$(printf '\t') read uid k; do
		echo "revoke_sig '${k}' '${uid}'"
		if revoke_sig "${k}" "${uid}"; then
			echo "${k}" >> to-send.txt || die 'failure writing to-send.txt'
		fi
	done < to-revoke.txt

	# sign new keys
	while IFS=$(printf '\t') read uid k; do
		if sign_key "${k}" "${uid}"; then
			echo "${k}" >> to-send.txt || die 'failure writing to-send.txt'
		fi
	done < to-sign.txt

	"${gpgcmd[@]}" -q --check-trustdb

	# Check if not sending keys.
	[[ ${AUTOSIGN_NO_SEND_KEYS} ]] && return

	keyservers=( hkps://keys.gentoo.org )
	# Try upload to ALL of the servers, in case there is weirdness
	raw_keyserver_options=$(dig +short _hosts.keys.gentoo.org  IN TXT \
			|tr -d '"' \
			|awk '/_hosts/{next} /gentoo.org/{h=gensub(".gentoo.org","",1,$1); printf "hkps://%s.keys.gentoo.org\n", h}'
		)
	for k in $raw_keyserver_options ; do
		keyservers+=( "$k" )
	done


	for keyserver in "${keyservers[@]}"; do
		cp -f to-send.src.txt to-send.txt
		# send key updates to the keyserver
		local retries=0
		while [[ -s to-send.txt ]]; do
			if gpg "${trust_args[@]}" --send-keys $(head -n 10 to-send.txt); then
				sed -i -e 1,10d to-send.txt || die 'failure writing to-send.txt'
			else
				[[ $(( ++retries )) -ge 5 ]] && break "send failure limit exceeded to $keyserver"
			fi
		done
	done
}

main "${@}"
