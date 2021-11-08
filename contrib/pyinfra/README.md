# pyinfra deployment of Hockeypuck

This directory contains a pyinfra deployment of hockeypuck, which can target
lxd or terraform.

## Supported tools

Currently using this deployment with:

```
$ pyinfra --version
pyinfra: v0.14.5
$ terraform --version
Terraform v0.13.5
```

## LXD deployment

Install LXD and run `pyinfra lxd.py hockeypuck.py`.

## GCP deployment

Edit google.tf to import your SSH key instead of mine. This could be
parameterized...

`terraform init` to set up the Google provider.

`terraform apply` to deploy the infrastructure.

`pyinfra tf.py hockeypuck.py` to install and configure hockeypuck. May fail
until cloud-init has a chance to complete and import your SSH key.

## Prometheus

Install prometheus on your hockeypuck server with the `prometheus.py`
operations script. It will be available on the default port 9000.

