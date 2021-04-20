/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const {config} = require('./wdio.shared.conf');

const domain = ".devl.trustbloc.dev"

exports.config = {
    ...config,
    "walletName": "wallet" + domain,
    "walletURL": "https://wallet" + domain,
    "issuerURL": "https://issuer" + domain,
    "verifierURL": "https://rp" + domain,
    "driversLicenseURL": "https://issuer" + domain + "/drivinglicense",
    "creditReportURL": "https://issuer" + domain + "/creditscore",
    "bankURL": "https://rp" + domain + "/bankaccount",
    "ucisURL": "https://ucis-rp" + domain,
    "cbpURL": "https://cbp-rp" + domain,
    "ucisInternalURL": "https://ucis-rp" + domain + "/internal",
    "fedSettlementURL": "https://benefits-dept-rp" + domain,

    capabilities: [{
        maxInstances: 5,
        browserName: 'chrome',
        // TODO enable headless chrome options - currently some cases are failing in headless mode
        // 'goog:chromeOptions': {
        //     // to run chrome headless the following flags are required
        //     // (see https://developers.google.com/web/updates/2017/04/headless-chrome)
        //     args: [
        //         '--headless',
        //         '--no-sandbox',
        //         '--disable-gpu',
        //         '--disable-dev-shm-usage',
        //         '--window-size 1920,1080',
        //     ],
        // }
    }],
    logLevel: 'warn',
};
