#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
export DEPLOYMENT_ENV			?= local
export DOMAIN      				?= ${DEPLOYMENT_ENV}.trustbloc.dev
export BLOC_DOMAIN				?= orb-1.${DOMAIN}
export TERM								?= xterm-256color
COMPONENTS         	 			?=
ISSUER_IMG_LOCAL         	 	?= ghcr.io/trustbloc/sandbox-issuer:latest
RP_IMG_LOCAL         	 		?= ghcr.io/trustbloc/sandbox-rp:latest
ACE_RP_IMG_LOCAL         	 	?= ghcr.io/trustbloc/sandbox-ace-rp:latest
LOGIN_CONSENT_IMG_LOCAL         ?= ghcr.io/trustbloc/sandbox-login-consent-server:latest
CLI_IMG_LOCAL         	 		?= ghcr.io/trustbloc/sandbox-cli:latest

.PHONY: deploy-all deploy-components setup-deploy ci-deploy-all ci-deploy-core ci-setup-deploy ci-minikube-setup local-setup-deploy minikube-up minikube-down minikube-image-load

undeploy-all:
	# TODO instead of delete all, run undeploy target on each component
	@kubectl delete all --all -n default
	echo "removed all components"

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
	@docker save $(ISSUER_IMG_LOCAL) > issuer_img_local.image
	@docker save $(RP_IMG_LOCAL) > rp_img_local.image
	@docker save $(ACE_RP_IMG_LOCAL) > ace_rp_img_local.image
	@docker save $(LOGIN_CONSENT_IMG_LOCAL) > login_consent_img_local.image
	@docker save $(CLI_IMG_LOCAL) > cli_img_local.image
	@minikube image load issuer_img_local.image
	@minikube image load rp_img_local.image
	@minikube image load ace_rp_img_local.image
	@minikube image load login_consent_img_local.image
	@minikube image load cli_img_local.image
	@rm issuer_img_local.image
	@rm rp_img_local.image
	@rm ace_rp_img_local.image
	@rm login_consent_img_local.image
	@rm cli_img_local.image

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
