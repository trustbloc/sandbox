/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

'use strict';

describe("TrustBloc - Validate Verifiable Credential(VC) and Verifiable Presentation(VP)", () => {
    // runs once before the first test in this block
    before(async () => {
        await browser.reloadSession();
        await browser.maximizeWindow();
    });

    it('Validate Verifiable Presentation(VP)', async function () {
        await browser.navigateTo(browser.config.verifierURL + '/demo');

        const vpTextarea = await $("#vpTextarea");
        await vpTextarea.clearValue();
        await vpTextarea.addValue({
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiablePresentation"],
            "holder": "did:key:z6MkwETtT2mP3L74iFCVSXeoVfTXBtgCN4HDuYjbQxxPcdm4",
            "verifiableCredential": [
              {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://www.w3.org/2018/credentials/examples/v1"
                ],
                "id": "http://example.gov/credentials/3732#4575be59-8537-40a5-990a-b9c689b0951a",
                "type": [
                  "VerifiableCredential",
                  "UniversityDegreeCredential"
                ],
                "issuer": "did:key:z6MkwETtT2mP3L74iFCVSXeoVfTXBtgCN4HDuYjbQxxPcdm4",
                "issuanceDate": "2021-09-14T18:54:13.510Z",
                "credentialSubject": {
                  "id": "did:key:z6MkwETtT2mP3L74iFCVSXeoVfTXBtgCN4HDuYjbQxxPcdm4",
                  "degree": {
                    "type": "BachelorDegree",
                    "name": "Bachelor of Science and Arts"
                  }
                },
                "proof": {
                  "type": "Ed25519Signature2018",
                  "created": "2021-09-14T18:55:00Z",
                  "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..YgGnEkHBhhtLOuZ_buxA4xQSOo4GI6MkvUGsWGVSOWwoe3e1gaD2TB5kpnOGluDJ3d1Xp2raVhy9pH0D4kPwCg",
                  "proofPurpose": "assertionMethod",
                  "verificationMethod": "did:key:z6MkwETtT2mP3L74iFCVSXeoVfTXBtgCN4HDuYjbQxxPcdm4#z6MkwETtT2mP3L74iFCVSXeoVfTXBtgCN4HDuYjbQxxPcdm4"
                }
              }
            ],
            "proof": {
              "type": "Ed25519Signature2018",
              "created": "2021-09-14T18:55:11Z",
              "challenge": "b0e21852-cce0-4117-b0b6-72b56abfb39e",
              "domain": "issuer.example.com",
              "jws": "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..VRrh2hgTMFFnfYJYmqDXIqfEptqTAgnfABCe_osf6oxuvLCrgBQzVowfo6tRYoxFsfhYrxUwPVecuy82fuoGAA",
              "proofPurpose": "authentication",
              "verificationMethod": "did:key:z6MkwETtT2mP3L74iFCVSXeoVfTXBtgCN4HDuYjbQxxPcdm4#z6MkwETtT2mP3L74iFCVSXeoVfTXBtgCN4HDuYjbQxxPcdm4"
            }
        });

        const validateBtn = await $('button*=Validate Presentation');
        await validateBtn.waitForClickable();
        await validateBtn.click();

        const successMsg = await $('div*=Validation Successful');
        await successMsg.waitForExist();
    })

    it('Validate Verifiable Credential(VC)', async function () {
        await browser.navigateTo(browser.config.verifierURL + '/demo');

        const credentialTab = await $('#credential');
        await credentialTab.waitForClickable();
        await credentialTab.click();

        const vcTextarea = await $("#vcTextarea");
        await vcTextarea.clearValue();
        await vcTextarea.addValue({
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://w3id.org/citizenship/v1"
            ],
            "id": "https://issuer.oidp.uscis.gov/credentials/83627465",
            "type": [
              "VerifiableCredential",
              "PermanentResidentCard"
            ],
            "name": "Permanent Resident Card",
            "description": "Government of Example Permanent Resident Card.",
            "issuanceDate": "2019-12-03T12:19:52Z",
            "expirationDate": "2029-12-03T12:19:52Z",
            "credentialSubject": {
              "id": "did:example:b34ca6cd37bbf23",
              "type": [
                "PermanentResident",
                "Person"
              ],
              "givenName": "JOHN",
              "familyName": "SMITH",
              "gender": "Male",
              "image": "data:image/png;base64,iVBORw0KGgo...kJggg==",
              "residentSince": "2015-01-01",
              "lprCategory": "C09",
              "lprNumber": "999-999-999",
              "commuterClassification": "C1",
              "birthCountry": "Bahamas",
              "birthDate": "1958-07-17"
            },
            "issuer": "did:key:z6MkiY62766b1LJkExWMsM3QG4WtX7QpY823dxoYzr9qZvJ3",
            "proof": {
              "type": "Ed25519Signature2018",
              "created": "2021-01-29T22:13:18Z",
              "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..sknzKI_uvf-7w4oTAFIgvBPJV4dUDTbBrHhUtRcyhyg8M4GxzA7_LYZL9GCyq6CT4ZoI7taidXDvOJEMGqmyCw",
              "proofPurpose": "assertionMethod",
              "verificationMethod": "did:key:z6MkiY62766b1LJkExWMsM3QG4WtX7QpY823dxoYzr9qZvJ3#z6MkiY62766b1LJkExWMsM3QG4WtX7QpY823dxoYzr9qZvJ3"
            }
        });

        const validateBtn = await $('button*=Validate Credential');
        await validateBtn.waitForClickable();
        await validateBtn.click();

        const successMsg = await $('div*=Validation Successful');
        await successMsg.waitForExist();
    })
})

