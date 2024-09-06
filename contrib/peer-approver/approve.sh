#!/usr/bin/env bash

ACCOUNTS_FILE=$1
INTERFACE_NAME=$2
PUBLIC_KEY=$3
ENDPOINT=$4
ADVANCED_SECURITY=$5

ACCOUNT_STR=`grep "${PUBLIC_KEY}" "${ACCOUNTS_FILE}"`

if [ "${ACCOUNT_STR}" == "" ]; then
  echo "Public key not found in accounts file!"
  exit 255
fi

ACCOUNT=(${ACCOUNT_STR//,/ })
ALLOWED_IPS=$(echo ${ACCOUNT[1]}|tr -d '"')
PSK=$(echo ${ACCOUNT[2]}|tr -d '"')
PSK_FILE=$(tempfile)
echo "${PSK}" > "${PSK_FILE}"

awg set "${INTERFACE_NAME}" peer "${PUBLIC_KEY}" allowed-ips "${ALLOWED_IPS}" endpoint "${ENDPOINT}" allowed-ips "${ALLOWED_IPS}" preshared-key "${PSK_FILE}" advanced-security "${ADVANCED_SECURITY}"
EXIT_CODE=$?

rm -f "{$PSK_FILE}"
exit ${EXIT_CODE}
