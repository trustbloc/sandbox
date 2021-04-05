#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

export DOMAIN      				?= trustbloc.dev
export DEPLOYMENT_ENV			?= local
COMPONENTS         	 			?=

.PHONY: deploy-all deploy-components setup-and-deploy minikube-setup minikube-down

deploy-all: deploy-core
	./scripts/deploy_all.sh

deploy-components:
	COMPONENTS="$(COMPONENTS)" ./scripts/deploy_all.sh

setup-and-deploy: minikube-down pull-core-deployment
	cd scripts && ./minikube_setup.sh
	@echo "Apply/verify the required changes to /etc/hosts. Once done, press ENTER" && read L
	make deploy-all -C ./.core
	./scripts/deploy_all.sh

minikube-setup: pull-core-deployment
	cd scripts && ./minikube_setup.sh

minikube-down:
	cd scripts && minikube delete ;

deploy-core:
	make deploy-all -C ./.core

pull-core-deployment:
	TRUSTBLOC_CORE_DEPLOYMENT_COMMIT="$(TRUSTBLOC_CORE_DEPLOYMENT_COMMIT)" ./scripts/core_deployment.sh

clean:
	@rm -rf ./.core/
