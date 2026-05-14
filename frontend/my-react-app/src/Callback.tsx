import { useEffect } from "react";
import { userManager } from "./auth";

export default function Callback() {

    useEffect(() => {
        userManager
            .signinRedirectCallback()
            .then(() => {
                window.location.href = "/";
            })
            .catch((err) => {
                console.error(err);
            });
    }, []);

    return <h2>Signing in...</h2>;
}