<!--
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
-->

<template>
    <div id="app">
        <div class="pt-16">
        <Navbar :navLabel="bank"/>
        </div>
        <section class="bg-white border-b py-48">
            <div class="container mx-auto flex  flex-wrap pt-4 pb-12">
                <div class="bg-blue w-full md:w-1/3 p-6 flex flex-col flex-grow flex-shrink">
                    <div class="flex-none mt-auto bg-white rounded-b rounded-t-none overflow-hidden p-6">
                        <div class=" flex items-center justify-center">
                            <form class="shadow-md rounded px-16 pt-8 pb-8 md:flex-wrap md:justify-between gradient">
                                <p class="text-white lg:text-2xl sm:text-xs text-center">Sign in to Online Banking</p>
                                <br>

                                <input type="hidden" name="challenge" v-bind:value="login_challenge">

                                <div class="mb-4">
                                    <label class="block text-white text-lg font-bold mb-2 text-left" for="email">
                                        Client Card or Username (required)
                                    </label>
                                    <input class="shadow appearance-none border w-full py-2 px-8 text-gray-700
                                leading-tight focus:outline-none focus:shadow-outline" name="username" type="tel" inputmode="numeric" pattern="[0-9\s]{13,19}" maxlength="19" value="4506 4456 4307 3456" required>
                                </div>

                                <div class="mb-6">
                                    <label class="block text-white text-lg font-bold mb-2 text-left" for="password">
                                        Password
                                    </label>
                                    <input class="shadow appearance-none border w-full py-2 px-8 text-gray-700 mb-3 leading-tight
                                focus:outline-none focus:shadow-outline" id="password" name='password' type="password" value="f00B@r!23">
                                    <p class="text-green-200 text-xs italic text-left">For demo password is optional.</p>
                                </div>
                                <div class="container flex-auto  mb-6">
                                <div class="w-full content-center mb-2 bg-yellow-400 py-2 text-center">
                                    <button class="mx-auto lg:mx-0  hover:underline font-bold text-xl text-black text-center" type='submit' id="accept" name='btn_login' v-on:click="postreqLogin()">
                                        Login
                                    </button>
                                </div>
                                </div>
                            </form>
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
    import Footer from '../components/Footer.vue'

    export default {
        name: 'bank-login-page',
        components: {
            Navbar,
            Footer
        },
        data() {
            return {
                login_challenge: "",
                bank: "Bank"
            }
        },
        methods: {
            postreqLogin: async function () {
                const loginUrl = "/login?challenge=" + this.$route.query.challenge + "&email=" + this.$route.query.username + "&password=" + this.$route.query.password
                await this.$http.post(loginUrl).then(
                    resp => {
                        if(resp.status !== 200) {
                            console.error(`failed to login: url=${loginUrl} status=${resp.status} err=${resp.data}`)
                            return
                        }
                        const redirectURL = resp.data.redirectURL
                        console.log(`logged in successfully; redirectURL=${redirectURL}`)
                        window.location.href = redirectURL
                        
                    },
                    err => {
                        console.error(`failed to login: url=${loginUrl} err=${err}`)
                        return;
                    }
                )
            }
        },
        created: function() {
            this.login_challenge = this.$route.query.login_challenge;
        }
    }
</script>