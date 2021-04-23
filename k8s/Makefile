#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
export DEPLOYMENT_ENV			?= local
export DOMAIN      				?= ${DEPLOYMENT_ENV}.trustbloc.dev
export BLOC_DOMAIN				?= testnet.${DOMAIN}
export TERM								?= xterm-256color
CURRENT_TIME					?= $(shell date +"%Y%m%dT%H%M%S%z")
COMPONENTS         	 			?=
ISSUER_IMG_LOCAL         	 	?= ghcr.io/trustbloc/sandbox-issuer:${CURRENT_TIME}
RP_IMG_LOCAL         	 		?= ghcr.io/trustbloc/sandbox-rp:${CURRENT_TIME}
ACE_RP_IMG_LOCAL         	 	?= ghcr.io/trustbloc/sandbox-ace-rp:${CURRENT_TIME}
LOGIN_CONSENT_IMG_LOCAL         ?= ghcr.io/trustbloc/sandbox-login-consent-server:${CURRENT_TIME}
CLI_IMG_LOCAL         	 		?= ghcr.io/trustbloc/sandbox-cli:${CURRENT_TIME}

.PHONY: deploy-all deploy-components setup-deploy ci-deploy-all ci-deploy-core ci-setup-deploy ci-minikube-setup local-setup-deploy minikube-up minikube-down minikube-image-load

deploy-all: deploy-core
	./scripts/deploy_all.sh

ci-deploy-all: ci-deploy-core
	./scripts/deploy_all.sh

deploy-components:
	COMPONENTS="$(COMPONENTS)" ./scripts/deploy_all.sh

setup-deploy: minikube-down minikube-up deploy-core deploy-all

ci-setup-deploy: ci-minikube-setup ci-deploy-core ci-deploy-all

local-setup-deploy: minikube-down minikube-up minikube-image-load deploy-core
	ISSUER_IMG=$(ISSUER_IMG_LOCAL) RP_IMG=$(RP_IMG_LOCAL) ACE_RP_IMG=$(ACE_RP_IMG_LOCAL) \
		LOGIN_CONSENT_IMG=$(LOGIN_CONSENT_IMG_LOCAL) CLI_IMG=$(CLI_IMG_LOCAL) \
		./scripts/deploy_all.sh

minikube-image-load:
	@echo "loading local images to minikube"
	@eval $(shell minikube docker-env)
	@docker tag ghcr.io/trustbloc/sandbox-issuer:latest $(ISSUER_IMG_LOCAL)
	@docker tag ghcr.io/trustbloc/sandbox-rp:latest $(RP_IMG_LOCAL)
	@docker tag ghcr.io/trustbloc/sandbox-ace-rp:latest $(ACE_RP_IMG_LOCAL)
	@docker tag ghcr.io/trustbloc/sandbox-login-consent-server:latest $(LOGIN_CONSENT_IMG_LOCAL)
	@docker tag ghcr.io/trustbloc/sandbox-cli:latest $(CLI_IMG_LOCAL)
	@minikube image load $(ISSUER_IMG_LOCAL)
	@minikube image load $(RP_IMG_LOCAL)
	@minikube image load $(ACE_RP_IMG_LOCAL)
	@minikube image load $(LOGIN_CONSENT_IMG_LOCAL)
	@minikube image load $(CLI_IMG_LOCAL)

ci-minikube-setup: pull-core-deployment
		cd scripts && ./ci_minikube_setup.sh

minikube-up: pull-core-deployment
	cd scripts && ./minikube_setup.sh
	@echo "Apply/verify the required changes to /etc/hosts. Once done, press ENTER" && read L

minikube-down:
	cd scripts && minikube delete ;

deploy-core:
	make deploy-all -C ./.core

ci-deploy-core:
	make SHELL=/bin/bash deploy-all -C ./.core

pull-core-deployment:
	TRUSTBLOC_CORE_K8S_COMMIT="$(TRUSTBLOC_CORE_K8S_COMMIT)" ./scripts/core_deployment.sh

clean:
	@rm -rf ./.core/
