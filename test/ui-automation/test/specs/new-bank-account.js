/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const {chapi, wallet, issuer, verifier} = require('../helpers');
const uuid = require('uuid-random');

describe("TrustBloc - New Bank Account", () => {
    const ctx = {
        email: `ui-aut-${new Date().getTime()}@test.com`,
    };

    // runs once before the first test in this block
    before(async () => {
        await browser.reloadSession();
        await browser.maximizeWindow();
    });

    beforeEach(function () {
    });

    it(`Register a Wallet (${ctx.email})`, async function () {
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

        // 3. select browser as default
        await issuer.selectBrowserWalletType()

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

        // 3. select browser as default
        await issuer.selectBrowserWalletType()

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

        // TODO https://github.com/trustbloc/sandbox/issues/990 select the vc and submit
    })
})

