const baseUrl = import.meta.env.VITE_API_URL || "";

export async function api(path, options = {}) {
  const response = await fetch(`${baseUrl}${path}`, {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed (${response.status})`);
  }
  return response.json();
}
