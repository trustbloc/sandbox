/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const {chapi, wallet, issuer, verifier} = require('../helpers');

describe("TrustBloc - WACI Share flow", () => {
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

    it('Issue Permanent Resident Card through CHAPI', async function () {
        // 1. Navigate to Issuer Website
        await browser.newWindow(browser.config.prcURL);

        const applyPRCBtn = await $('#applyprc');
        await applyPRCBtn.waitForClickable();
        await applyPRCBtn.click();

        const loginBtn = await $('#login');
        await loginBtn.waitForClickable();
        await loginBtn.click();

        const lookupBtn = await $('#lookupSubmit');
        await lookupBtn.waitForClickable();
        await lookupBtn.click();

        const authBtn = await $('#authBtn');
        await authBtn.waitForClickable();
        await authBtn.click();

        // 2. Authenticate at Issuer Website with Wallet
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.authenticate(ctx);
        await browser.switchToFrame(null);

        // 3. Issue credential to authenticated DID at Issuer Website
        const storeBtn = await $('#storeprc');
        await storeBtn.waitForClickable();
        await storeBtn.click();

        // 4. Store credential with Wallet
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.storeCredentials(ctx);
        await browser.switchToFrame(null);

        // 5. Show success message at Issuer Website
        const successMsg1 = await $('div*=Your Digital Permanent Resident Card has been stored successfully');
        await successMsg1.waitForExist();

        // wait for any async operations to complete
        browser.executeAsync((done) => {
            setTimeout(done, 5000)
        })
    })

    it('Verify Permanent Resident Card (WACI Share - Redirect)', async function () {
        // 1. Navigate prc verifier
        await browser.navigateTo(browser.config.prcWACI);

        // 2. connect to RP adapter
        const getCredentialButton = await $('#prCard');
        await getCredentialButton.waitForClickable();
        await getCredentialButton.click();

        // 3. use redirect flow
        const driversLicenseVC = await $('a*=Click here to redirect to your wallet');
        await driversLicenseVC.waitForClickable();
        await driversLicenseVC.click()

        // 4. share prc
       // TODO validate PRC VC

        const shareCredBtn = await $('#share-credentials');
        await shareCredBtn.waitForClickable();
        await shareCredBtn.click();

        // 5. validate success msg
        const verifySuccessMsg = await $('div*=Successfully Verified');
        await verifySuccessMsg.waitForExist();

        // TODO validate response data

        const proceedBtn = await $('#proceedClick');
        await proceedBtn.waitForClickable();
        await proceedBtn.click();

        const successMsg = await $('div*=Your Permanent Resident Card Verified Successfully');
        await successMsg.waitForExist();
    })
})

