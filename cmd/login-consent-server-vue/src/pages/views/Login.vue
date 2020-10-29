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
                            <form class="bg-white shadow-md rounded px-32 pt-8 pb-8 md:flex-wrap md:justify-between">
                                <p class="text-black text-xl">Login to your account</p>
                                <br>

                                <input type="hidden" name="challenge" v-bind:value="login_challenge">

                                <div class="mb-4">
                                    <label class="block text-gray-700 text-sm font-bold mb-2 text-left" for="email">
                                        Email
                                    </label>
                                    <input class="shadow appearance-none border rounded w-full py-2 px-8 text-gray-700
                                leading-tight focus:outline-none focus:shadow-outline" type='email' name='email' id='email' value="john.smith@example.com" required>
                                </div>

                                <div class="mb-6">
                                    <label class="block text-gray-700 text-sm font-bold mb-2 text-left" for="password">
                                        Password
                                    </label>
                                    <input class="shadow appearance-none border rounded w-full py-2 px-8 text-gray-700 mb-3 leading-tight
                                focus:outline-none focus:shadow-outline" id="password" name='password' type="password" value="f00B@r!23">
                                    <p class="text-green-500 text-xs italic text-left">For demo password is optional.</p>
                                </div>

                                <div class="flex items-center justify-center">
                                    <button class="mx-auto lg:mx-0 hover:underline gradient text-white font-bold rounded-full my-4 py-2 px-8 shadow-lg" type="submit" id="accept" name='btn_login' v-on:click="postreqLogin()">
                                        Login
                                    </button>
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
    import Flow from '../components/Flow.vue'
    import Footer from '../components/Footer.vue'

    export default {
        name: 'login-page',
        components: {
            Navbar,
            Flow, 
            Footer
        },
        data() {
            return {
                login_challenge: ""
            }
        },
        methods: {
            postreqLogin: async function () {
                const loginUrl = "/login?challenge=" + this.$route.query.challenge + "&email=" + this.$route.query.email + "&password=" + this.$route.query.password
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
