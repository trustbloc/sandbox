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

    it('Connect to Credit Report Issuer (pre-action)', async function () {
        await browser.pause(3000)

        // 1. Navigate to Credit report issuer
        await browser.newWindow(browser.config.creditReportURL);

        // 2. Issuer login and consent
        await issuer.loginConsent('#creditScore')

        // 3. select browser as default
        await issuer.selectBrowserWalletType()
    })

    it('Connect to Credit Report Issuer', async function () {
        await browser.pause(3000)

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
            setTimeout(done, 5000)
        })
    })

    it('Get Drivers License and Connect to Assurance Issuer', async function () {
        await browser.pause(3000)

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
            setTimeout(done, 5000)
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

        // 4. select VCs
        const driversLicenseVC = await $('span*=Drivers License');
        await driversLicenseVC.waitForClickable();
        await driversLicenseVC.click()
        // TODO: verify that the credential details show up with correct info

        const creditReportVC = await $('span*=TrustBloc - Credit Report Issuer');
        await creditReportVC.waitForClickable();
        await creditReportVC.click()

        const assuranceIssuerVC = await $('span*=TrustBloc - Driving License + Assurance Issuer');
        await assuranceIssuerVC.waitForClickable();
        await assuranceIssuerVC.click()

        const shareCredBtn = await $('#share-credentials');
        await shareCredBtn.waitForClickable();
        await shareCredBtn.click();

        // 5. validate success msg
        const verifySuccessMsg = await $('div*=Successfully Verified');
        await verifySuccessMsg.waitForExist();

        const proceedBtn = await $('#proceedClick');
        await proceedBtn.waitForClickable();
        await proceedBtn.click();

        const successMsg = await $('div*=Your Bank Account Is Successfully Opened');
        await successMsg.waitForExist();
    })
})

