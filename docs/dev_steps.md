## Component update in Sandbox

1. Fork the [TrustBloc k8s repo](https://github.com/trustbloc/k8s).
2. Link the k8s repo to sandbox repo as described [here](../k8s/scripts/core_deployment.sh).
3. Update the component details in k8s repo or sandbox repo as applicable ie, docker image tag, configurations etc.
4. If there is no sandbox code changes, then run `make setup-deploy`, if not `make build-setup-deploy`.
5. Once all the components are up, run the test automation script `make automation-test`. Not: The tests run in headless chrome mode. To change it 
to chrome, comment the headless chrome options in (./../test/ui-automation/wdio.shared.conf.js).
6. Create a PR in [TrustBloc k8s repo](https://github.com/trustbloc/k8s).
7. Update the k8s commit version in sandbox repo and create a PR in sandbox repo - [Reference PR](https://github.com/trustbloc/sandbox/pull/1027/files).
8. The CI will build the sandbox components, deploy and run the automation tests.
9. Once merged, update the sandbox docker version in the repo and create a PR - [Reference PR](https://github.com/trustbloc/sandbox/pull/1029/files)
