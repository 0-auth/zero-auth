import type { ConsentContext, ErrorContext, IdentityProviderUi, LoginContext } from "./types.js";

export function escapeHtml(value: string): string {
  return value.replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character]!
  );
}

function page(title: string, content: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
  </head>
  <body>
    <main>${content}</main>
  </body>
</html>`;
}

function renderLogin(context: LoginContext): string {
  const error = context.error ? `<p role="alert">${escapeHtml(context.error)}</p>` : "";

  return page(
    "Sign in",
    `<h1>Sign in</h1>
${error}
<form method="post" action="${escapeHtml(context.action)}">
  <input type="hidden" name="transaction" value="${escapeHtml(context.transactionId)}">
  <input type="hidden" name="csrf_token" value="${escapeHtml(context.csrfToken)}">
  <label>Email <input type="email" name="email" autocomplete="email" required></label>
  <label>Password <input type="password" name="password" autocomplete="current-password" required></label>
  <button type="submit">Continue</button>
</form>`
  );
}

function renderConsent(context: ConsentContext): string {
  const scopes = context.scopes.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("");

  return page(
    "Authorize application",
    `<h1>Authorize ${escapeHtml(context.clientName)}</h1>
<p>This application is requesting:</p>
<ul>${scopes}</ul>
<form method="post" action="${escapeHtml(context.action)}">
  <input type="hidden" name="transaction" value="${escapeHtml(context.transactionId)}">
  <input type="hidden" name="csrf_token" value="${escapeHtml(context.csrfToken)}">
  <button type="submit" name="decision" value="deny">Deny</button>
  <button type="submit" name="decision" value="allow">Allow</button>
</form>`
  );
}

function renderError(context: ErrorContext): string {
  return page(
    "Authentication error",
    `<h1>Authentication error</h1><p>${escapeHtml(context.message)}</p>`
  );
}

export const defaultUi: Required<IdentityProviderUi> = {
  renderLogin,
  renderConsent,
  renderError,
};
