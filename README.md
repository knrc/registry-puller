# Registry Puller Webhook

This repository contains code for a webhook which monitors the creation of ServiceAccounts within kubernetes namespaces and modifies those ServiceAccounts so they include an additional image pull secret.  This is of use when trying to deploy containers referencing private repos.

# Building the registry-puller

This is handled through the Makefile, execute make to build the operator and container

* make

# Running the webhook

The following steps will install the webhook into an existing OpenShift deployment, instructions for kubernetes will be similar

* download your secret and create a file called secret.yaml
* oc new-project registry-puller
* oc create configmap -n registry-puller registry-secret --from-file=secret.yaml

For OpenShift 3.11 execute

* oc create -f registry-puller-3.11.yaml

For OpenShift 4.0 execute

* oc create -f registry-puller-4.0.yaml
