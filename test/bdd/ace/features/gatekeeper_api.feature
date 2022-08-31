#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@gatekeeper
Feature: Gatekeeper API
  @gatekeeper_e2e
  Scenario: Protect and extract social media handle (e2e flow)
    Given did owner with name "Intake Processor"
      And did owner with name "Handler"
      And did owner with name "Approver 1"
      And did owner with name "Approver 2"
      And policy configuration with ID "full-scenario-policy"
          """
          {
            "collectors": ["{{ .GetDID "Intake Processor" }}"],
            "handlers": ["{{ .GetDID "Handler" }}"],
            "approvers": ["{{ .GetDID "Approver 1" }}", "{{ .GetDID "Approver 2" }}"],
            "min_approvers": 2
          }
          """

    When  an HTTP POST with "(request-target),date,digest" headers signed by "Intake Processor" is sent to "https://GATEKEEPER_HOST/v1/protect" with body
          """
          {
            "target": "@thanos27",
            "policy": "full-scenario-policy"
          }
          """
    Then  response status is "200 OK"
     And  response contains non-empty "did"

    When  an HTTP POST with "(request-target),date,digest" headers signed by "Handler" is sent to "https://GATEKEEPER_HOST/v1/release" with body
          """
          {
            "did": "{{ .Value "did" }}"
          }
          """
    Then  response status is "200 OK"
     And  response contains non-empty "ticket_id"

    When  an HTTP POST with "(request-target),date" headers signed by "Approver 1" is sent to "https://GATEKEEPER_HOST/v1/release/{ticket_id}/authorize"
    Then  response status is "200 OK"

    When  an HTTP POST with "(request-target),date" headers signed by "Approver 2" is sent to "https://GATEKEEPER_HOST/v1/release/{ticket_id}/authorize"
    Then  response status is "200 OK"

    When  an HTTP POST with "(request-target),date" headers signed by "Handler" is sent to "https://GATEKEEPER_HOST/v1/release/{ticket_id}/collect"
    Then  response status is "200 OK"
     And  response contains non-empty "query_id"

    When  an HTTP POST is sent to "https://GATEKEEPER_HOST/v1/extract"
          """
          {
            "query_id": "{{ .Value "query_id" }}"
          }
          """
    Then  response status is "200 OK"
     And  response contains "target" with value "@thanos27"
