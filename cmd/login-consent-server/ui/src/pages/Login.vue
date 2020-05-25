<template>
    <div>
        <navbar-component></navbar-component>
        <main>
            <section class="absolute w-full h-full">
                <div class="container mx-auto px-4 h-full">
                    <div class="flex content-center items-center justify-center h-full">
                        <div class="w-full lg:w-5/12 px-4">
                            <div class="relative flex flex-col min-w-0 break-words w-full mb-6 shadow-lg rounded-lg bg-gray-300 border-0">
                                <div class="rounded-t mb-0 px-6 py-6">
                                    <div class="text-center mb-3">
                                        <h6 class="text-gray-600 text-sm font-bold">
                                            Login in with credentials
                                        </h6>
                                    </div>
                                </div>
                                <div class="flex-auto px-4 lg:px-10 py-10 pt-0">
                                    <form action="/login" method="post">
                                        <input type="hidden" name="challenge" value=${.login_challenge}>
                                        <div class="relative w-full mb-3">
                                            <label class="block uppercase text-gray-700 text-xs font-bold mb-2"
                                                    for="grid-password">Email</label><input
                                                type="email"
                                                class="px-3 py-3 placeholder-gray-400 text-gray-700 bg-white rounded text-sm shadow focus:outline-none focus:shadow-outline w-full"
                                                value="foo@bar.com" required
                                                style="transition: all 0.15s ease 0s;"/>
                                        </div>
                                        <div class="relative w-full mb-3">
                                            <label class="block uppercase text-gray-700 text-xs font-bold mb-2"
                                                    for="grid-password">Password</label><input
                                                type="password"
                                                class="px-3 py-3 placeholder-gray-400 text-gray-700 bg-white rounded text-sm shadow focus:outline-none focus:shadow-outline w-full"
                                                value="foobar"
                                                style="transition: all 0.15s ease 0s;"/>
                                        </div>
                                        <div>
                                            <label class="inline-flex items-center cursor-pointer"><input
                                                    id="customCheckLogin"
                                                    type="checkbox"
                                                    class="form-checkbox text-gray-800 ml-1 w-5 h-5"
                                                    style="transition: all 0.15s ease 0s;"/>
                                                <span class="ml-2 text-sm font-semibold text-gray-700">Remember me</span></label>
                                        </div>
                                        <div class="text-center mt-6">
                                            <button
                                                    class="bg-blue-800 text-white active:bg-blue-700 text-sm font-bold uppercase px-6 py-3 rounded shadow hover:shadow-lg outline-none focus:outline-none mr-1 mb-1 w-full
                                                    transition duration-500 ease-in-out bg-blue-500 hover:bg-green-500 transform hover:-translate-y-1 hover:scale-110"
                                                    type="button"
                                                    style="transition: all 0.15s ease 0s;">
                                                Login In
                                            </button>
                                        </div>
                                    </form>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                <footer-component></footer-component>
            </section>
        </main>
    </div>
</template>
<script>
    import NavbarComponent from "../components/Navbar.vue";
    import FooterComponent from "../components/Footer.vue";
    export default {
        components: {
            NavbarComponent,
            FooterComponent
        }
    }
</script>
