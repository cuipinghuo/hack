# e2e Tests

## Cluster

Use clusterbot to create a new cluster:

```text
workflow-launch hypershift-hostedcluster-workflow 4.12 HYPERSHIFT_NODE_COUNT=3
```

Install RHTAP on the cluster:

```bash
cd ~/src/redhat-appstudio/infra-deployments
git pull

./hack/bootstrap-cluster.sh preview --keycloak --toolchain
```

## Setup

Use a custom quay.io organization:

```bash
export QUAY_E2E_ORGANIZATION=cuipinghuo
```

Copy local creds to the cluster so images can be pushed to repos
in the quay.io org above:

```bash
kubectl create namespace e2e-secrets

kubectl -n e2e-secrets create secret docker-registry quay-repository \
    --from-file=.dockerconfigjson=$HOME/.docker/config.json
```

## Execute

To run the Enterprise Contract e2e tests:

```bash
make build && ./bin/e2e-appstudio --ginkgo.label-filter=ec --ginkgo.v
```

