/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const {chapi, wallet, issuer, verifier} = require('../helpers');
const path = require('path');
const uuid = require('uuid-random');

describe("TrustBloc - New Bank Account", () => {
    const ctx = {
        email: `${uuid()}@example.com`,
    };

    // runs once before the first test in this block
    before(async () => {
        await browser.reloadSession();
        await browser.maximizeWindow();
    });

    beforeEach(function () {
    });

    it('Register a Wallet', async function () {
        this.timeout(300000);

        // 1. Navigate to Wallet Website
        await browser.navigateTo(browser.config.walletURL);

        // 2. Initialize Wallet (register/sign-up/etc.)
        await wallet.init(ctx);
    });

    it('Get Drivers License and Connect to Assurance Issuer', async function () {
        // 1. Navigate to Drivers license + Assurance issuer
        await browser.newWindow(browser.config.driversLicenseURL);

        // 2. Issuer login and consent
        await issuer.loginConsent('#drivingLicense')

        // 3. add cookie to select browser as default (TODO: find a way to do this without modifying cookies)
        browser.addCookie({'pref.wallet.type.100': 'broswer'})

        // 4. choose wallet
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });

        // 5. didconnect
        await wallet.didConnect()

        browser.executeAsync((done) => {
            setTimeout(done, 10000)
        })
    })

    it('Connect to Credit Report Issuer', async function () {
        // 1. Navigate to Credit report issuer
        await browser.newWindow(browser.config.creditReportURL);

        // 2. Issuer login and consent
        await issuer.loginConsent('#creditScore')

        // 3. add cookie to select browser as default (TODO: find a way to do this without modifying cookies)
        browser.addCookie({'pref.wallet.type.100': 'broswer'})

        // 4. choose wallet
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });

        // 5. didconnect
        await wallet.didConnect()

        browser.executeAsync((done) => {
            setTimeout(done, 10000)
        })
    })

    it('Open a Bank Account', async function () {
        // 1. Navigate bank website
        await browser.newWindow(browser.config.bankURL);

        // 2. connect to RP adapter
        await verifier.adapterCredentials('#prCard')

        // 3. choose wallet
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });

        const successMsg1 = await $('div*=Drivers License');
        await successMsg1.waitForExist();

        // TODO select the vc and submit
    })
})

