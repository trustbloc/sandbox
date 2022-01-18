/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const {chapi, wallet, issuer} = require('../helpers');

describe("TrustBloc - [PRC] Duty Free Shop Use Case (WACI Issuance + WACI Share flow)", () => {
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

    it('Issue Permanent Resident Card (WACI Issuance - Redirect)', async function () {
        // 1. Navigate to Issuer Website
        await browser.newWindow(browser.config.issuerURL);

        // 2. Authenticate at Issuer Website with Wallet
        await issuer.authenticate({ credential: 'PermanentResidentCardWACI', skipDIDAuth: true});

        const redirectMsg = await $('a*=Click here to redirect to your wallet');
        await redirectMsg.waitForClickable();
        await redirectMsg.click()

        // 3. preview and store vc at wallet
        const prCardCred = await $('div*=Permanent Resident Card');
        await prCardCred.waitForExist();
        
        const lastNameFieldName = await $('td*=Family Name');
        await lastNameFieldName.waitForExist();

        const lastName = await $('td*=Pasteur');
        await lastName.waitForExist();

        await new Promise((resolve) => setTimeout(resolve, 2000));

        const storeBtn = await $('#storeVCBtn');
        await storeBtn.waitForClickable();
        await storeBtn.click();

        const okBtn = await $("#issue-credentials-ok-btn");
        await okBtn.waitForExist();
        await okBtn.click()

        // 4. validate success message at the issuer
        const successMsg = await $('div*=Your credential(s) have been stored in your digital wallet.');
        await successMsg.waitForExist();

        // wait for any async operations to complete
        browser.executeAsync((done) => {
            setTimeout(done, 5000)
        })
    })

    it.skip('Validate Permanent Resident Card in Wallet', async function () {
        this.timeout(300000);

        // 1. Navigate to Credentials page on Wallet Website
        await browser.navigateTo(`${browser.config.walletURL}`);

        const credentialsLink = await $("#navbar-link-credentials");
        await credentialsLink.click();

        // 2. Check if the credential is stored
        const checkStoredCredential = await $('div*=Permanent Resident Card');
        await checkStoredCredential.waitForExist();
    });

    it('Present Permanent Resident Card at Duty Free Shop (WACI Share - Redirect)', async function () {
        // 1. Navigate prc verifier
        await browser.navigateTo(browser.config.dutyFreeShop);

        // 2. connect to RP adapter
        const getCredentialButton = await $('#prCard');
        await getCredentialButton.waitForClickable();
        await getCredentialButton.click();

        // 3. use redirect flow
        const redirectMsg = await $('a*=Click here to redirect to your wallet');
        await redirectMsg.waitForClickable();
        await redirectMsg.click()

        // 4. share prc
        const prCardCred = await $('div*=Permanent Resident Card');
        await prCardCred.waitForExist();

        const shareCredBtn = await $('#share-credentials');
        await shareCredBtn.waitForClickable();
        await shareCredBtn.click();

        const sharedBtn = await $('#share-credentials-ok-btn');
        await sharedBtn.waitForClickable();
        await sharedBtn.click();

        // 5. validate success msg
        const verifySuccessMsg = await $('div*=Successfully Verified');
        await verifySuccessMsg.waitForExist();

        const lastNameFieldName = await $('td*=Family Name');
        await lastNameFieldName.waitForExist();

        const lastName = await $('td*=Pasteur');
        await lastName.waitForExist();

        const proceedBtn = await $('#proceedClick');
        await proceedBtn.waitForClickable();
        await proceedBtn.click();

        const successMsg = await $('div*=Your Permanent Resident Card Verified Successfully');
        await successMsg.waitForExist();
    })
})

