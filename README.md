# Registry Puller Webhook

This repository contains code for a webhook which monitors the creation of ServiceAccounts within kubernetes namespaces and modifies those ServiceAccounts so they include an additional image pull secret.  This is of use when trying to deploy containers referencing private repos.

# Running the webhook

The following steps will install the webhook into an existing OpenShift deployment, instructions for kubernetes will be similar

* download your secret and create a file called secret.yaml
* make
* oc new-project registry-puller
* oc create configmap -n registry-puller registry-secret --from-file=secret.yaml
* oc create -f registry-puller.yaml
