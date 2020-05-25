<template>
    <div>
        <navbar-component></navbar-component>
        <main>
            <section class="absolute w-full h-full">
                <div class="absolute top-0 w-full h-full bg-white">
                </div>
                <div class="container mx-auto px-4 h-full">
                    <div class="flex content-center items-center justify-center h-full">
                        <div class="container my-24">
                            <div class="max-w-3xl rounded shadow-lg">
                                <div class="px-6 py-4 bg-gray-100">
                                    <div class="font-bold text-xl text-green-600 mb-2">An application requests access to your data</div>
                                    <form action="" method="POST">
                                       <!-- TODO -->
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

