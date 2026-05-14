import { useEffect, useState } from "react";
import { User } from "oidc-client-ts";
import { logout, userManager } from "./auth";

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

  if (!user) return <h2>Redirecting...</h2>;

  return (
    <div>
      <h1>Home Page</h1>

      <p>Welcome: {user.profile.sub}</p>

      <button onClick={logout}>
        Logout
      </button>
    </div>
  );
}

export default App;