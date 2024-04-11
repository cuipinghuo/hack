#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

DEBUG_OUTPUT=/tmp/log.txt

export ACS__API_TOKEN \
  ACS__CENTRAL_ENDPOINT \
  DEVELOPER_HUB__CATALOG__URL \
  GITHUB__APP__APP_ID GITHUB__APP__CLIENT_ID \
  GITHUB__APP__CLIENT_SECRET \
  GITHUB__APP__WEBHOOK_SECRET \
  GITHUB__APP__PRIVATE_KEY \
  DEVELOPER_HUB__QUAY_TOKEN__ASK_THE_INSTALLER_DEV_TEAM \
  GITOPS__GIT_TOKEN \
  QUAY__DOCKERCONFIGJSON \
  TAS__SECURESIGN__FULCIO__ORG_EMAIL \
  TAS__SECURESIGN__FULCIO__ORG_NAME \
  TAS__SECURESIGN__FULCIO__OIDC__URL \
  TAS__SECURESIGN__FULCIO__OIDC__CLIENT_ID \
  TAS__SECURESIGN__FULCIO__OIDC__TYPE \
  TPA__GUAC__PASSWORD \
  TPA__KEYCLOAK__ADMIN_PASSWORD \
  TPA__MINIO__ROOT_PASSWORD \
  TPA__OIDC__TESTING_MANAGER_CLIENT_SECRET \
  TPA__OIDC__TESTING_USER_CLIENT_SECRET \
  TPA__OIDC__WALKER_CLIENT_SECRET \
  TPA__POSTGRES__POSTGRES_PASSWORD \
  TPA__POSTGRES__TPA_PASSWORD \
  RHTAP_ENABLE_GITHUB \
  RHTAP_ENABLE_GITLAB \
  RHTAP_ENABLE_DEVELOPER_HUB \
  RHTAP_ENABLE_TAS \
  RHTAP_ENABLE_TAS_FULCIO_OIDC_DEFAULT_VALUES \
  RHTAP_ENABLE_TPA \
  SPRAYPROXY_SERVER_URL \
  SPRAYPROXY_SERVER_TOKEN

  # OPENSHIFT_API \
  # OPENSHIFT_PASSWORD \
  # GITHUB__APP__WEBHOOK_URL # no need


RHTAP_ENABLE_GITHUB=${RHTAP_ENABLE_GITHUB:-'true'} 
RHTAP_ENABLE_GITLAB=${RHTAP_ENABLE_GITLAB:-'false'}
RHTAP_ENABLE_DEVELOPER_HUB=${RHTAP_ENABLE_DEVELOPER_HUB:-'true'}
RHTAP_ENABLE_TAS=${RHTAP_ENABLE_TAS:-'true'}
RHTAP_ENABLE_TAS_FULCIO_OIDC_DEFAULT_VALUES=${RHTAP_ENABLE_TAS_FULCIO_OIDC_DEFAULT_VALUES:-'true'}
RHTAP_ENABLE_TPA=${RHTAP_ENABLE_TPA:-'true'}

# Need to ask team for shared details
DEVELOPER_HUB__QUAY_TOKEN__ASK_THE_INSTALLER_DEV_TEAM=""
TPA__GUAC__PASSWORD=""                                                # notsecret
TPA__KEYCLOAK__ADMIN_PASSWORD=""                                      # notsecret
TPA__MINIO__ROOT_PASSWORD=""                                          # notsecret
TPA__OIDC__TESTING_MANAGER_CLIENT_SECRET=""                           # notsecret
TPA__OIDC__TESTING_USER_CLIENT_SECRET=""                              # notsecret
TPA__OIDC__WALKER_CLIENT_SECRET=""                                    # notsecret
TPA__POSTGRES__POSTGRES_PASSWORD=""                                   # notsecret
TPA__POSTGRES__TPA_PASSWORD=""                                        # notsecret
TAS__SECURESIGN__FULCIO__ORG_EMAIL='rhtap-qe-ci@redhat.com'
TAS__SECURESIGN__FULCIO__ORG_NAME='RHTAP CI Jobs'
TAS__SECURESIGN__FULCIO__OIDC__URL='http://localhost:3030' # no need
TAS__SECURESIGN__FULCIO__OIDC__CLIENT_ID="fake-one" # no need
TAS__SECURESIGN__FULCIO__OIDC__TYPE="dex" # no need

# Need to customize
ACS__API_TOKEN=""
ACS__CENTRAL_ENDPOINT=""
DEVELOPER_HUB__CATALOG__URL=https://github.com/redhat-appstudio/tssc-sample-templates/blob/main/all.yaml
GITHUB__APP__APP_ID=
GITHUB__APP__CLIENT_ID=""
GITHUB__APP__CLIENT_SECRET=""
GITHUB__APP__WEBHOOK_SECRET=""
github_app_private_key_path=""
GITHUB__APP__PRIVATE_KEY=$(cat $github_app_private_key_path)
QUAY__DOCKERCONFIGJSON='{"auths":{"quay.io/xxxx":{"auth":"","email": ""}}}'
GITOPS__GIT_TOKEN=""

NAMESPACE=rhtap

clean_up() {
  echo "[INFO]Clean up resources..."
  if [ -f "private-values.yaml" ]; then
    rm private-values.yaml
    echo "Deleted private-values.yaml"
  fi
  if [ -f "private.env" ]; then
    rm private.env
    echo "Deleted private.env"
  fi
}

clone_repo() {
  echo "[INFO]Cloning rhtap-installer repo..."
  git clone https://github.com/redhat-appstudio/rhtap-installer.git
  cd rhtap-installer
}

wait_for_pipeline() {
  if ! oc wait --for=condition=succeeded "$1" -n "$2" --timeout 300s >"$DEBUG_OUTPUT"; then
    echo "[ERROR] Pipeline failed to complete successful" >&2
    oc get pipelineruns "$1" -n "$2" >"$DEBUG_OUTPUT"
    exit 1
  fi
}

install_rhtap() {
  echo "[INFO]Generate private-values.yaml file ..."
  ./bin/make.sh values
  # enable debug model
  yq e -i '.debug.script=true' private-values.yaml

  echo "[INFO]Install RHTAP ..."
  ./bin/make.sh apply -d -n $NAMESPACE -- --values private-values.yaml

  echo ""
  echo "[INFO]Extract the configuration information from logs of the pipeline"
  cat <<EOF >rhtap-pe-info.yaml
    apiVersion: tekton.dev/v1
    kind: PipelineRun
    metadata:
      generateName: rhtap-pe-info-
      namespace: "$NAMESPACE"
    spec:
      pipelineSpec:
        tasks:
          - name: configuration-info
            taskRef:
              resolver: cluster
              params:
                - name: kind
                  value: task
                - name: name
                  value: rhtap-pe-info
                - name: namespace
                  value: "$NAMESPACE"
EOF

  pipeline_name=$(oc create -f rhtap-pe-info.yaml | cut -d' ' -f1 | awk -F'/' '{print $2}')
  wait_for_pipeline "pipelineruns/$pipeline_name" "$NAMESPACE"
  tkn -n "$NAMESPACE" pipelinerun logs "$pipeline_name" -f >"$DEBUG_OUTPUT"

  homepage_url=$(grep "homepage-url" <"$DEBUG_OUTPUT" | sed 's/.*: //g')
  callback_url=$(grep "callback-url" <"$DEBUG_OUTPUT" | sed 's/.*: //g')
  webhook_url=$(grep "webhook-url" <"$DEBUG_OUTPUT" | sed 's/.*: //g')

  echo "$homepage_url"
  echo "$callback_url"
  echo "$webhook_url"
}

e2e_test() {
  echo "[INFO]Trigger installer sanity tests..."
  ./bin/make.sh -n "$NAMESPACE" test
}

register_pac_server() {
  # if SPRAYPROXY_SERVER_URL and SPRAYPROXY_SERVER_TOKEN are not set, we suppose the spraypray server is installed in the same cluster
  if [ -z "${SPRAYPROXY_SERVER_URL:-}" ]; then
    SPRAYPROXY_SERVER_URL=https://$(kubectl -n sprayproxy get route sprayproxy-route -o jsonpath="{.spec.host})")
  fi

  if [ -z "${SPRAYPROXY_SERVER_TOKEN:-}" ]; then
    SPRAYPROXY_SERVER_TOKEN=$(kubectl -n sprayproxy get secret sprayproxy-secret -o jsonpath='{.data.token}' | base64 -d)
  fi

  echo "Start registering PAC server [$webhook_url] to SprayProxy server"
  for _ in {1..5}; do
    if curl -k -X POST -H "Authorization: Bearer ${SPRAYPROXY_SERVER_TOKEN}" "${SPRAYPROXY_SERVER_URL}"/backends --data '{"url": "'"$webhook_url"'"}'; then
      break
    fi
    sleep 5
  done
}

jwt_token() {
  app_id=$1     # App ID as first argument
  pem=$(cat "$2") # file path of the private key as second argument

  now=$(date +%s)
  iat=$((now - 60))  # Issues 60 seconds in the past
  exp=$((now + 600)) # Expires 10 minutes in the future

  b64enc() { openssl base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n'; }

  header_json='{
      "typ":"JWT",
      "alg":"RS256"
  }'
  # Header encode
  header=$(echo -n "${header_json}" | b64enc)

  payload_json='{
      "iat":'"${iat}"',
      "exp":'"${exp}"',
      "iss":'"${app_id}"'
  }'
  # Payload encode
  payload=$(echo -n "${payload_json}" | b64enc)

  # Signature
  header_payload="${header}"."${payload}"
  signature=$(
      openssl dgst -sha256 -sign <(echo -n "${pem}") \
          <(echo -n "${header_payload}") | b64enc
  )

  # Create JWT
  JWT_TOKEN="${header_payload}"."${signature}"
}

update_github_app() {
  echo "Update GitHub App"
  curl \
    -X PATCH \
    -H "Accept: application/vnd.github.v3+json" \
    -H "Authorization: Bearer $JWT_TOKEN" \
    https://api.github.com/app/hook/config \
    -d "{\"content_type\":\"json\",\"insecure_ssl\":\"0\",\"secret\":\"$GITHUB__APP__WEBHOOK_SECRET\",\"url\":\"$webhook_url\"}" &>/dev/null
}

clean_up
#clone_repo
install_rhtap
e2e_test
jwt_token "$GITHUB__APP__APP_ID" "$github_app_private_key_path"
update_github_app
# register_pac_server
