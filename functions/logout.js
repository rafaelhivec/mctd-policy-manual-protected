// /logout route: clears the site access cookie.
const COOKIE_NAME = "site_access";

export async function onRequest(context) {
  const url = new URL(context.request.url);
  const redirectTo = url.searchParams.get("r") || "/";

  const headers = new Headers();
  headers.set("Set-Cookie", `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  headers.set("Location", redirectTo.startsWith("/") ? redirectTo : "/");
  return new Response(null, { status: 302, headers });
}
