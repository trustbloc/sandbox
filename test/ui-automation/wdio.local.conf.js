/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const {config} = require('./wdio.shared.conf');

const domain = ".local.trustbloc.dev"

exports.config = {
    ...config,
    "walletName": "wallet" + domain,
    "walletURL": "https://wallet" + domain,
    "issuerURL": "https://demo-issuer" + domain,
    "verifierURL": "https://demo-rp" + domain,
    "driversLicenseURL": "https://demo-issuer" + domain + "/drivinglicense",
    "creditReportURL": "https://demo-issuer" + domain + "/creditscore",
    "applyPrCardURL": "https://demo-issuer" + domain + "/applyprcard",
    "bankURL": "https://demo-rp" + domain + "/bankaccount",
    "ucisURL": "https://ucis-rp" + domain,
    "cbpURL": "https://cbp-rp" + domain,
    "ucisInternalURL": "https://ucis-rp" + domain + "/internal",
    "fedSettlementURL": "https://benefits-dept-rp" + domain,
    "prcURL": "https://demo-issuer" + domain + "/applygreencard",
    "backgroundCheckURL": "https://demo-rp" + domain + "/backgroundcheck",
    "flightBookingURL": "https://demo-issuer" + domain + "/flightbooking",
    "flightBoardingURL": "https://demo-rp" + domain + "/flightcheckin",
    "dutyFreeShop": "https://demo-rp" + domain + "/dutyfree",
    "issuePrCardURL": "https://demo-issuer" + domain + "/issueprcard",
    "local" : true,
    // chapi
    isCHAPIEnabled: true,
};
