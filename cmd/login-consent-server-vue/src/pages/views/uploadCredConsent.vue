<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div id="app">
        <Navbar/>
        <div class="pt-12">
            <div class="container px-3 mx-auto flex flex-wrap flex-col md:flex-row items-center">
                <!--Left Col-->
                <div class="flex flex-col w-full md:w-2/5 justify-center items-start text-center md:text-left">
                    <h1 class="my-4 text-5xl font-bold leading-tight"></h1>
                </div>
            </div>
        </div>
        <Flow/>
       <section class="bg-white border-b py-24">
            <div class="container mx-auto flex  flex-wrap pt-4 pb-12">
                <div class="w-full md:w-1/3 p-6 flex flex-col flex-grow flex-shrink">
                    <div class="flex-none mt-auto bg-white rounded-b rounded-t-none overflow-hidden p-6">
                        <div class="flex items-center justify-center">
                            <div class="max-w-3xl rounded shadow-lg">
                                <img class="object-scale-down h-48 w-full" src="img/consent.png">
                                <div class="px-6 py-4 bg-gray-100 justify-center">
                                    <p class="font-bold text-xl text-black mb-2">An application requests access to your data</p>
                                    <form>
                                        <p class="text-gray-700 text-base"><strong>{{ClientID}}</strong> wants access resources on your behalf:</p>
                                        <label class="md:w-2/3 block text-gray-500 font-bold" v-for="scope in Scopes" :key="scope">
                                            <input class="mr-2 leading-tight filled-in" type="checkbox" v-bind:id="scope" v-bind:value="scope" name="grant_scope" checked="checked" />
                                            <span class="text-lg text-black" id="scopeName" v-bind:for="scope">{{scope}}</span>
                                        </label>
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
</template>

<script>
    import Navbar from '../components/Navbar.vue'
    import Flow from '../components/Flow.vue'
    import Footer from '../components/Footer.vue'

    export default {
        name: 'consent-page',
        components: {
            Navbar,
            Flow, 
            Footer
        },
        data() {
            return {
                User: "",
                ClientID: "",
                Challenge: "",
                Scopes: []
            }
        },
        methods: {
            postreqConsent: async function() {
                var name = document.getElementById("scopeName").innerText
                var scopeName =  this.getScopeName(name);
                document.getElementById("scopeName").innerText = scopeName;
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
            },
            getScopeName: function (name) {
                var scopes = {
                    'mDL': 'Driving License',
                    'StudentCard': 'Student Card',
                    'TravelCard': 'Travel Card',
                    'UniversityDegreeCredential': 'University Degree',
                    'CertifiedMillTestReport': 'Credit Mill Test Report',
                    'CrudeProductCredential': 'Crude Product Credential',
                    'PermanentResidentCard': 'Permanent Resident Card',
                    'CreditCardStatement': 'Credit Card Statement',
                    'CreditScore': 'Credit Score Report',
                };
                return scopes[name];
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
                    this.Scopes = resp.data.scopes
                },
                err => {
                    console.error(`failed to get consent data: url=${consentUrl} err=${err}`)
                    return;
                }
            )
        }
    }
</script>
