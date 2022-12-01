#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

@all
@issuer
Feature: Issuer Pre-Authorize
  @issuer_pre_authorize_e2e
  Scenario: Execute PreAuthorize flow
    Given User wants to receive credentials with format "jwt_vc" and type "VerifiedEmployee"
    When User request issuer to start pre-authorization flow
    Then no error is occurred