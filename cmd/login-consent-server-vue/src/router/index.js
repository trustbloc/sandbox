import Login from "@/pages/views/Login";
import Consent from "@/pages/views/Consent";

const routes = [
    {
        path: "/login",
        component: Login,
        name: 'Login'
    },
    {
        path: '/consent',
        component: Consent,
        name: 'Consent'
    }
];

export default routes;
