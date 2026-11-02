SUCCESS_CONFIG_FILE="./logs-success-${1}/output.log"
FAIL_CONFIG_FILE="./logs-fail-${1}/output.log"
INVALID_CONFIG_FILE="./logs-invalid-${1}/output.log"

echo "RUNNING TESTS FOR ${1}"
echo " - Succ $SUCCESS_CONFIG_FILE"
echo " - Fail $FAIL_CONFIG_FILE"
echo " - Inva $INVALID_CONFIG_FILE"

sleep 1s

if ! grep -q "X-Is-Trusted: yes" $SUCCESS_CONFIG_FILE; then
  echo "'X-Is-Trusted: yes' header was not added and parsed ($SUCCESS_CONFIG_FILE)"
  exit 5
fi
if ! grep -qE "^X-Forwarded-For: ${2}[[:space:]]*$" $SUCCESS_CONFIG_FILE; then
  echo "'X-Forwarded-For: ${2}' header not defined, or not alone ($SUCCESS_CONFIG_FILE)"
  exit 5
fi
#if ! grep -q "X-Real-Ip: 10.0.0.2" $SUCCESS_CONFIG_FILE; then
#  echo "IP real not defined"
#  exit 5
#fi
if ! grep -q "Cf-Visitor: {\"scheme\":\"https\"}" $SUCCESS_CONFIG_FILE; then
  echo "'Cf-Visitor: {\"scheme\":\"https\"}' header not defined ($SUCCESS_CONFIG_FILE)"
  exit 5
fi
if ! grep -q "cloudflarewarp: IP list updated" "./logs-success-${1}/debug.log"; then
  echo "The Cloudflare IP list was not downloaded (./logs-success-${1}/debug.log)"
  exit 5
fi

if ! grep -q "X-Is-Trusted: no" $FAIL_CONFIG_FILE; then
  echo "'X-Is-Trusted: no' header was not added to the invalid request ($FAIL_CONFIG_FILE)"
  exit 5
fi
# disableDefault only shows from a source IP inside a Cloudflare range, which the routing mesh of stack mode rules out
if [ ! "${3}" = "stack" ] && ! grep -q "X-Real-Ip: 103.21.244." $FAIL_CONFIG_FILE; then
  echo "The request did not come from a Cloudflare IP, disableDefault was not tested ($FAIL_CONFIG_FILE)"
  exit 5
fi
if ! grep -q "X-Is-Trusted: no" $INVALID_CONFIG_FILE; then
  echo "'X-Is-Trusted: no' header was not added to the invalid request ($INVALID_CONFIG_FILE)"
  exit 5
fi
#if ! grep -q "X-Forwarded-For: 10.0.0.2" $FAIL_CONFIG_FILE; then
#  echo "Forwarded header was not defined as the original IP"
#  exit 5
#fi

echo "TESTS OK"
