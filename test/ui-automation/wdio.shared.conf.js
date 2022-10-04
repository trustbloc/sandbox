/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';
const mergeResults = require('wdio-mochawesome-reporter/mergeResults');
const path = require('path');
const outputDir = path.resolve(__dirname, 'reports');
exports.config = {
    runner: 'local',
    specs: [
        './test/specs/ace.js',
        './test/specs/credential-validations.js',
        './test/specs/waci-flow.js',
        './test/specs/oidc-flow.js',
        './test/specs/new-bank-account.js',
        './test/specs/flight-boarding.js',
        './test/specs/vcs-flow.js',
        './test/specs/vcs-revocation.js',
        './test/specs/uscis-login-flow.js'
    ],
    // Maximum number of total parallel running workers
    maxInstances: 1,
    capabilities: [
        {
            // Maximum number of total parallel running workers per capability
            maxInstances: 5,
            browserName: 'chrome',
            'goog:chromeOptions': {
                // to run chrome headless the following flags are required
                // (see https://developers.google.com/web/updates/2017/04/headless-chrome)
                args: [
                    '--headless',
                    '--no-sandbox',
                    '--disable-gpu',
                    '--disable-dev-shm-usage',
                    '--window-size=1920,1080',
                    '--disable-web-security',
                    '--ignore-certificate-errors',
                ],
            },
        },
    ],

    // Level of logging verbosity: trace | debug | info | warn | error | silent
    logLevel: 'warn',
    baseUrl: 'http://localhost',

    // Default timeout for all waitFor* commands.
    waitforTimeout: 60000,

    // Default timeout in milliseconds for request
    // if browser driver or grid doesn't send response
    connectionRetryTimeout: 120000,

    // Default request retries count
    connectionRetryCount: 3,

    // Test runner services
    services: ['chromedriver'],

    // Framework you want to run your specs with.
    framework: 'mocha',

    reporters: [
        'spec',
        ['junit', {
            outputDir,
            outputFileFormat: function (options) {
                return `wdio-results-${options.cid}-junit-report.xml`;
            }
        }],
        ['mochawesome', {
            outputDir,
            outputFileFormat: function (opts) {
                return `mochawesome-results-${opts.cid}.json`;
            }
        }]
    ],
    mochawesomeOpts: {
        includeScreenshots: true,
        screenshotUseRelativePath: true
    },

    // Options to be passed to Mocha.
    mochaOpts: {
        ui: 'bdd',
        timeout: 120000,
    },
    // eslint-disable-next-line no-unused-vars
    onComplete: function (exitCode, config, capabilities, results) {
        mergeResults(outputDir, 'mochawesome-results-*');
    }
};
