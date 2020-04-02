# Registry Puller Webhook

This repository contains code for a webhook which monitors the creation of ServiceAccounts within kubernetes namespaces and modifies those ServiceAccounts so they include an additional image pull secret.  This is of use when trying to deploy containers referencing private repos.

# Building the Registry Puller

Building the registry puller is handled through the Makefile. Clone this as a Go project and execute make to build the operator and container. These instructions assume you are putting the source in "$HOME/source" - change this to match your file structure.

```
SRC_DIR="$HOME/source"
export GOPATH="${SRC_DIR}/registry-puller"
mkdir -p ${GOPATH}/src/github.com/knrc
cd ${GOPATH}/src/github.com/knrc
git clone git@github.com:knrc/registry-puller.git
cd registry-puller
make
```

make will build a container image `knrc/registry-puller:1.1`:

```
[your_login@localhost registry-puller]$ sudo docker images knrc/registry-puller:1.1
REPOSITORY             TAG                 IMAGE ID            CREATED             SIZE
knrc/registry-puller   1.1                 b7aa1d34b2a1        23 hours ago        241 MB
[your_login@localhost registry-puller]$
```

If needed, tag and push this image to the image repository your OpenShift cluster has access to, and update the image reference in the corresponding registry-puller-*.yaml file, like so:

```
[your_login@localhost registry-puller]$ git diff registry-puller-4.0.yaml
diff --git a/registry-puller-4.0.yaml b/registry-puller-4.0.yaml
index af6e85e..2ac3960 100644
--- a/registry-puller-4.0.yaml
+++ b/registry-puller-4.0.yaml
@@ -111,7 +111,7 @@ spec:
     serviceAccountName: registry-puller
       containers:
         - name: registry-puller
-          image: "knrc/registry-puller:1.0"
+          image: "quay.io/your_login/registry-puller:1.0"
           imagePullPolicy: IfNotPresent
           ports:
           - name: webhook
[your_login@localhost registry-puller]$
```

# Running the webhook

The following steps will install the webhook into an existing OpenShift deployment, instructions for kubernetes will be similar

* create a secret with the login credentials for the image registry your need to access
* download your secret and create a file called secret.yaml in your current working directory
  - the name of the file has to be secret.yaml as a key with that name will be created in the registry-secret ConfigMap and the registry puller will look for it. In registry-puller-*.yaml, here is the corresponding command line parameter:
	  ```
      - --registry-secret-file
      - /etc/registry-secret/secret.yaml
	  ```
  - remove all metadata fields but name and namespace from the downloaded secret
* oc new-project registry-puller
* oc create configmap -n registry-puller registry-secret --from-file=secret.yaml

For OpenShift 3.11 execute

* oc create -f registry-puller-3.11.yaml

For OpenShift 4.0 and above execute

* oc create -f registry-puller-4.0.yaml

# Registry Puller in action

To see the registry puller in action, create a new project in OpenShift. The registry puller will attach the secret you specified as an image pull secret to the default ServiceAccount in the new namespace:

```
[your_login@localhost]$ oc describe sa default -n your_project
Name:                default
Namespace:           your_project
Labels:              <none>
Annotations:         <none>
Image pull secrets:  your_secret
                     default-dockercfg-hxnrt
Mountable secrets:   default-dockercfg-hxnrt
                     default-token-bv4cb
Tokens:              default-token-bv4cb
                     default-token-slzmr
Events:              <none>
[your_login@localhost]$
```

Now you can deploy images from the repository "your_secret" contains credentials for, into your_project.
