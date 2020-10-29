<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->


<template>
    <div id="app">
        <div class="pt-16">
        <Navbar :navLabel="bank"/>
        <section class="bg-white border-b py-4">
            <div class="container mx-auto flex  flex-wrap pt-4 pb-12">
                <div class="w-full md:w-1/3 p-6 flex flex-col flex-grow flex-shrink">
                    <div class="flex-none mt-auto bg-white rounded-b rounded-t-none overflow-hidden p-6">
                        <div class="flex items-center justify-center">
                            <div class="max-w-3xl rounded shadow-lg">
                                <div class="px-6 py-4 bg-white justify-center">
                                    <p class="font-bold text-xl text-black mb-2 text-center">Terms of Service</p>
                                    <p class="lg:text-lg sm:text-sm text-black mb-2">Use of this service is governed by the following terms and conditions. Please read these terms and conditions carefully, as by using this website you will be deemed to have agreed to them. If you do not agree with these terms and conditions, do not use this service.

                                        TrustBloc Flow provides user with a way to obtaining their digital ID as a Verifiable Credential.

                                        The personal information you provide ((Name, Email, Date of Birth and Address etc) will be used for the purpose of issuing the Verified Person credential under the authority of section 33(a) of the Freedom of Information and Protection of Privacy Act. You will be able to receive your "Open" Verified Person credential on online user wallet. TrustBloc’s collection of your personal information is under the authority of section 26(c) of the Freedom of Information and Protection of Privacy Act.

                                        If you have any questions about our collection or use of personal information, please direct your inquiries to the TrustBloc Dev team on github.</p>
                                    <p class="font-bold text-xl text-black mb-2 text-center">Limitation of Liabilities</p>
                                    <p class="lg:text-lg sm:text-sm text-black mb-2">Under no circumstances will the TrustBloc Application be liable to any person or business entity for any direct, indirect, special, incidental, consequential, or other damages based on any use of this website or any other website to which this site is linked, including, without limitation, any lost profits, business interruption, or loss of programs or information, even if the Government has been specifically advised of the possibility of such damages.</p>
                                    <div class="divide-y divide-gray-700">
                                        <div class="text-center py-2"></div>
                                        <div class="text-center py-2"></div>
                                    </div>
                                    <form>
                                        <p class="text-black text-lg"><input class="mr-2 leading-tight filled-in" type="checkbox" name="agree" checked="checked" />
                                            I agree with the above terms and conditions {{User}} , application <strong>{{ClientID}}</strong> can access the resource</p>
                                        <br>
                                        <div>
                                            <input type="hidden" name="consent_challenge" v-bind:value="Challenge">
                                        <div class="grid grid-cols-2 gap-8">
                                            <div>
                                                <button type="submit" name="submit" id="reject" class="col-start-1 col-end-2 bg-transparent hover:bg-red-700 text-black font-semibold hover:text-white px-4 py-2 m-2 border border-red-500 hover:border-transparent rounded"      value="reject" v-on:click="postreqConsent()">Deny</button>
                                            </div>
                                            <div class="flex justify-end">
                                                <button type="submit" name="submit" id="accept" class="col-end-2 col-span-2 bg-transparent hover:bg-green-400 text-green-700 font-semibold hover:text-white px-4 py-2 m-2 border border-green-500 hover:border-transparent rounded"  value="accept" v-on:click="postreqConsent()">Agree</button>
                                            </div>
                                        </div>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

            </div>
        </section>
        <Footer/>
        </div>
    </div>
</template>

<script>
    import Navbar from '../components/Navbar.vue'
    import Footer from '../components/Footer.vue'

    export default {
        name: 'bank-consent-page',
        components: {
            Navbar,
            Footer
        },
        data() {
            return {
                User: "",
                ClientID: "",
                Challenge: "",
                bank: "Bank"
            }
        },
        methods: {
            postreqConsent: async function() {
                const consentUrl = "/consent?consent_challenge=" + this.$route.query.consent_challenge + "&submit=" + this.$route.query.submit
                await this.$http.post(consentUrl).then(
                    resp => {
                        if(resp.status !== 200) {
                            console.error(`failed: url=${consentUrl} status=${resp.status} err=${resp.data}`)
                            return
                        }
                        const redirectURL = resp.data.redirectURL
                        console.log(`success; redirectURL=${redirectURL}`)
                        window.location.href = redirectURL
                        
                    },
                    err => {
                        console.error(`failed: url=${consentUrl} err=${err}`)
                        return;
                    }
                )
            }
        },
        created: async function() {
            const consentUrl = "/consent"
            await this.$http.get(consentUrl).then (
                resp => {
                    if (resp.status !== 200) {
                        console.error(`failed to get consent data: url=${consentUrl} status=${resp.status} err=${resp.data}`)
                        return
                    }
                    this.User = resp.data.user
                    this.CliendID = resp.data.clientid
                    this.Challenge = resp.data.challenge
                },
                err => {
                    console.error(`failed to get consent data: url=${consentUrl} err=${err}`)
                    return;
                }
            )
        }
    }
</script>