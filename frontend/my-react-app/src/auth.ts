import { UserManager, WebStorageStateStore } from "oidc-client-ts";

export const userManager = new UserManager({
    authority: "http://localhost:8080",
    client_id: "react-client",
    redirect_uri: "http://localhost:5173/callback",
    response_type: "code",
    scope: "openid profile api.read",

    userStore: new WebStorageStateStore({ store: window.sessionStorage })
});

export const logout = async () => {
    const user = await userManager.getUser();

    // 1. Clear local session
    await userManager.removeUser();

    // 2. Redirect to Spring logout (clears JSESSIONID)
    window.location.href = "http://localhost:8080/logout";
};