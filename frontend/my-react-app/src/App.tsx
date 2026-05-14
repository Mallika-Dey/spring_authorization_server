import { useEffect, useState } from "react";
import { User } from "oidc-client-ts";
import { logout, refreshTokens, userManager } from "./auth";

let loginStarted = false;

function App() {
  const [user, setUser] = useState<User | null>(null);

  useEffect(() => {
    userManager.getUser().then((u) => {
      if (u) {
        setUser(u);
        return;
      }

      if (!loginStarted) {
        loginStarted = true;
        userManager.signinRedirect();
      }
    });
  }, []);

    const handleRefresh = async () => {
    try {
      const oldUser = await userManager.getUser();

      console.log("OLD ACCESS TOKEN:");
      console.log(oldUser?.access_token);

      console.log("OLD REFRESH TOKEN:");
      console.log(oldUser?.refresh_token);

      const newUser = await refreshTokens();

      setUser(newUser);

      console.log("NEW ACCESS TOKEN:");
      console.log(newUser.access_token);

      console.log("NEW REFRESH TOKEN:");
      console.log(newUser.refresh_token);

      alert("Tokens refreshed. Check console.");
    } catch (e) {
      console.error(e);
    }
  };

  if (!user) return <h2>Redirecting...</h2>;

  return (
    <div>
      <h1>Home Page</h1>

      <p>Welcome: {user.profile.sub}</p>
    <br />
      <button onClick={handleRefresh}>
        Test Refresh Token Rotation
      </button>
      <br />
      <button onClick={logout}>
        Logout
      </button>
    </div>
  );
}

export default App;