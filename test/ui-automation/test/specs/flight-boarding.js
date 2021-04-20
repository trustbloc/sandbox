/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const {chapi, wallet, issuer, verifier} = require('../helpers');
const uuid = require('uuid-random');

describe("TrustBloc - Flight Boarding", () => {
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

    it('Issue Vaccination Certificate', async function () {
        // 1. Navigate to Issuer Website
        await browser.newWindow(browser.config.issuerURL);

        // 2. Authenticate at Issuer Website with Wallet
        await issuer.authenticate({credential: 'VaccinationCertificate'});
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.authenticate(ctx);
        await browser.switchToFrame(null);

        // 3. Issue credential to authenticated DID at Issuer Website
        await issuer.issue(ctx);

        // 4. Store credential with Wallet
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.storeCredentials(ctx);
        await browser.switchToFrame(null);

        // 5. Show success message at Issuer Website
        await issuer.finish(ctx);

        // wait for any async operations to complete
        browser.executeAsync((done) => {
            setTimeout(done, 10000)
        })
    })

    it('Issue Permanent Residence Card', async function () {
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
            setTimeout(done, 10000)
        })
    })

    it('Issue Booking Reference', async function () {
        // 1. Navigate to Issuer Website
        await browser.newWindow(browser.config.flightBookingURL);

        const linkWalletBtn = await $('#linkWalletBtn');
        await linkWalletBtn.waitForClickable();
        await linkWalletBtn.click();

        // 2. Authenticate at Issuer Website with Wallet
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.authenticate(ctx);
        await browser.switchToFrame(null);

        // 3. Issue credential to authenticated DID at Issuer Website
        const bookingBtn = await $('#bookingBtn');
        await bookingBtn.waitForClickable();
        await bookingBtn.click();

        // 4. Store credential with Wallet
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });
        await wallet.storeCredentials(ctx);
        await browser.switchToFrame(null);

        // 5. Show success message at Issuer Website
        const successMsg1 = await $('div*=Congratulations! Your flight booking is confirmed');
        await successMsg1.waitForExist();

        // wait for any async operations to complete
        browser.executeAsync((done) => {
            setTimeout(done, 10000)
        })
    })

    it('Flight Check-in with Permanent Residence Card, Booking Reference ' +
        'and Selective discloure of Vaccination Certificate details', async function () {
        // 1. Navigate bank website
        await browser.newWindow(browser.config.flightBoardingURL);

        const checkinBtn = await $('#checkin');
        await checkinBtn.waitForClickable();
        await checkinBtn.click();

        // 2. connect to RP adapter
        const selectiveDisclosureBtn = await $('#selectiveDisclosure');
        await selectiveDisclosureBtn.waitForClickable();
        await selectiveDisclosureBtn.click();

        // 3. choose wallet
        await chapi.chooseWallet({
            name: browser.config.walletName,
        });

        const shareCredBtn = await $('#share-credentials');
        await shareCredBtn.waitForClickable();
        await shareCredBtn.click();

        const checkinMsg = await $('div*=Check-In Successful');
        await checkinMsg.waitForExist();

        const getBoardingPassBtn = await $('#release');
        await getBoardingPassBtn.waitForClickable();
        await getBoardingPassBtn.click();

        const boardingPassMsg = await $('div*=Boarding pass');
        await boardingPassMsg.waitForExist();
    })
})

