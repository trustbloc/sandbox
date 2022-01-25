/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

const constants = require('./constants');
const {allow} = require('./chapi');

const DIDS = constants.dids
const timeout = 60000;

/*************************** Public API ******************************/

exports.signUp = async ({createDID, importDID, email}) => {
    // login and consent
    await _getSignUp(email);
    // register chapi
    await allow()

    // wait for credentials
    await _waitForCredentials();

    // setup DIDs if required.
    if (importDID) {
        await _saveAnyDID({method: importDID});
    } else if (createDID) {
        await _createTrustblocDID({method: createDID});
    }
};

exports.authenticate = async ({did}) => {
    await _didAuth({method: did})
};

exports.storeCredentials = async () => {
    await _acceptCredentials();
};

exports.presentCredentials = async ({did}) => {
    await _sendCredentials({method: did});
};

exports.didConnect = async () => {
    const didConnectBtn = await $('#didconnect');
    await didConnectBtn.waitForExist();
    await didConnectBtn.waitForClickable();
    await didConnectBtn.click();

    const successMsg = await $('div*=CONGRATULATIONS ');
    await successMsg.waitForExist();
};

exports.signOut = async () => {
    await _signOutWallet();
};

exports.signIn = async ({email}) => {
    await _signIn(email);
};

exports.checkStoredCredentials = async (credName) => {
    await _checkStoredCredentials(credName);
};

exports.deleteCredentials = async (credName) => {
    await _deleteCredential(credName);
};

exports.changeLocale = async () => {
    await _changeLocale();
};

/*************************** Helper functions ******************************/

async function _didAuth({method = 'trustbloc'} = {}) {
    const authenticate = await $('#didauth')
    await authenticate.waitForExist();
    await authenticate.click();
}

async function _acceptCredentials() {
    const storeBtn = await $('#storeVCBtn');
    await storeBtn.waitForExist();
    await storeBtn.waitForClickable();
    await storeBtn.click();
}

async function _sendCredentials({method = "trustbloc"} = {}) {
    // share
    const shareBtn = await $('#share-credentials')
    await shareBtn.waitForExist();
    await shareBtn.waitForClickable();
    await shareBtn.click();
}

async function _getSignUp(email) {
    const signUpButton = await $('#mockbank');
    await signUpButton.waitForExist();
    await signUpButton.click();
    await _getThirdPartyLogin(email);
}

async function _signOutWallet() {
    const signOutButton = await $('button*=Sign Out');
    await signOutButton.waitForExist();
    await signOutButton.click();

    // wait for logout to complele and go to signup page
    await browser.waitUntil(async () => {
        const headingLink = await $('h1*=Sign up.');
        expect(headingLink).toHaveValue('Sign up.');
        return true;
    });
}

async function _signIn(email) {
    await browser.waitUntil(async () => {
        const signInButton = await $('#mockbank');
        await signInButton.waitForExist();
        await signInButton.click();
        await _getThirdPartyLogin(email);
        return true;
    });
}


async function _changeLocale() {
    const localeSwitcherLink = await $('a*=Français');
    await localeSwitcherLink.waitForExist();
    await localeSwitcherLink.click();
    await browser.waitUntil(async () => {
        const headingLink = await $('h1*=Inscrivez-vous. C’est gratuit!');
        expect(headingLink).toHaveValue('Inscrivez-vous. C’est gratuit!');
        return true;
    });
}

async function _getThirdPartyLogin(email) {
    await browser.waitUntil(async () => {
        try {
            await browser.switchWindow('Login Page');
        } catch (err) {
            console.warn("[warn] switch window to login page : ", err.message)
            return false
        }
        return true
    });


    await browser.waitUntil(async () => {
        let emailInput = await $('#email');
        await emailInput.waitForExist();
        expect(emailInput).toHaveValue('john.smith@example.com');
        await emailInput.setValue(email);
        return true;
    });

    const loginInButton = await $('#accept');
    await loginInButton.click();

    await browser.switchWindow(browser.config.walletURL)
    await browser.waitUntil(async () => {
        let title = await $('iframe');
        await title.waitForExist({timeout, interval: 5000});
        return true;
    });
}

async function _waitForCredentials() {
    await browser.waitUntil(async () => {
      const defaultValut = await $("div*=Default Vault");
      await defaultValut.click();

      const credentialsLink = await $("#navbar-link-credentials");
      await credentialsLink.click();
      let didResponse = await $("#loaded-credentials-container");
      await didResponse.waitForExist({ timeout, interval: 5000 });
      expect(didResponse).toBeDisplayed();
      return true;
    });
  }

async function _checkStoredCredentials(credName) {
    const credentialsLink = await $("#navbar-link-credentials");
    await credentialsLink.click();

    const checkStoredCredential = await $('div*=' + credName);
    return await checkStoredCredential.waitForExist();
}

async function _deleteCredential(credName) {
    const storedCred = await $("span*=" + credName);
    await storedCred.waitForExist();
    await storedCred.click();

    const flyoutMenuImage = await $('#credential-details-flyout-button');
    await flyoutMenuImage.waitForExist();
    await flyoutMenuImage.waitForClickable();
    await flyoutMenuImage.click();

    const deleteButton = await $('button*=Delete Credential');
    await deleteButton.waitForExist();
    await deleteButton.waitForClickable();
    await deleteButton.click();

    const deleteConfirmButton = await $('#delete-credential-button');
    await deleteConfirmButton.waitForExist();
    await deleteConfirmButton.waitForClickable();
    await deleteConfirmButton.click();
};

async function _saveAnyDID({method}) {
    const didManager = await $('a*=Settings');
    await didManager.waitForExist();
    await didManager.click();

    const saveAnyDID = await $('button*=Save Any Digital Identity');
    await saveAnyDID.waitForExist();
    await saveAnyDID.click();

    if (!DIDS[method]) {
        throw `couldn't find did method '${did} in test config'`
    }

    // enter DID
    const didInput = await $('#did');
    await didInput.addValue(DIDS[method].did);

    // enter private key JWK
    const privateKeyJWK = await $('#privateKeyJwk');
    await privateKeyJWK.addValue(DIDS[method].pkjwk);

    // enter KEY ID
    const keyID = await $('#keyID');
    await keyID.addValue(DIDS[method].keyID);

    // select signature Type
    const signType = await $('#selectSignKey');
    await signType.addValue(DIDS[method].signatureType);

    // enter friendly name
    const friendlyName = await $('#anyDIDFriendlyName');
    await friendlyName.addValue(DIDS[method].name);

    const submit = await $('#saveDIDBtn')
    submit.click()

    await browser.waitUntil(async () => {
        let didResponse = await $('#save-anydid-success');
        await didResponse.waitForExist({timeout, interval: 2000});
        expect(didResponse).toHaveText('Saved your DID successfully.');
        return true;
    });

    console.log('saved DID successfully !!')
}


async function _createTrustblocDID() {
    const didManager = await $('a*=Settings');
    await didManager.waitForExist();
    await didManager.click();

    const didDashboard = await $('button*=Digital Identity Dashboard');
    await didDashboard.waitForExist();
    await didDashboard.click();

    // select key Type
    const keyType = await $('#selectKey');
    await keyType.addValue(DIDS.trustbloc.keyType);

    // select signature Type
    const signType = await $('#signKey');
    await signType.addValue(DIDS.trustbloc.signatureType);

    // enter friendly name
    const friendlyName = await $('#friendlyName');
    await friendlyName.addValue(DIDS.trustbloc.name);

    const submit = await $('#createDIDBtn')
    submit.click()

    await browser.waitUntil(async () => {
        let didResponse = await $('#create-did-success');
        await didResponse.waitForExist({timeout, interval: 2000});
        expect(didResponse).toHaveText('Saved your DID successfully.');
        return true;
    });

    console.log('created trustbloc DID successfully !!')
}
